// A staged signup (keypair + DEK in the pending slots) is either promoted by
// save_session_code, answered again by a prepare retried with the same input,
// or dropped by auth_signup_abort after the server refused it. Any other
// prepare is refused, so a second signup can never replace a key the server
// may already hold (Q8).

package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// signupStageMu serialises the staged-signup check with the staging and the
// abort in this process. Keychain helpers used inside take the keychain
// process lock themselves, so that lock cannot be held around them.
var signupStageMu sync.Mutex

const signupInputDomain = "dragpass-signup-prepare-input-v1"

// signupInputRecord is stored next to the staged signup. The hash is PBKDF2
// at the password-wrap cost, so the record is no cheaper a password oracle
// than the password-wrapped DEK the server already holds.
type signupInputRecord struct {
	Version     int    `json:"v"`
	Fingerprint string `json:"public_key_fingerprint"`
	AccountID   string `json:"account_id"`
	Salt        string `json:"salt"`
	Hash        string `json:"hash"`
}

func signupInputHash(fingerprint, accountID, alias string, recoveryKey []byte, password *memguard.LockedBuffer, salt []byte) []byte {
	var canonical []byte
	for _, field := range [][]byte{[]byte(signupInputDomain), []byte(fingerprint), []byte(accountID), []byte(alias), recoveryKey, password.Bytes()} {
		canonical = binary.BigEndian.AppendUint32(canonical, uint32(len(field)))
		canonical = append(canonical, field...)
	}
	defer secure.Zeroize(canonical)
	return pbkdf2.Key(canonical, salt, dekPBKDF2Iterations, 32, sha256.New)
}

func newSignupAccountID(d Deps) (string, error) {
	var raw [16]byte
	if err := d.FillRandom(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func newSignupInputRecord(d Deps, publicKey, accountID, alias string, recoveryKey []byte, password *memguard.LockedBuffer) (string, error) {
	salt := make([]byte, 16)
	if err := d.FillRandom(salt); err != nil {
		return "", err
	}
	fingerprint := crypto.AccountKeyFingerprint([]byte(publicKey))
	record, err := json.Marshal(signupInputRecord{
		Version:     1,
		Fingerprint: fingerprint,
		AccountID:   accountID,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Hash:        base64.StdEncoding.EncodeToString(signupInputHash(fingerprint, accountID, alias, recoveryKey, password, salt)),
	})
	return string(record), err
}

func readSignupAccountID(d Deps) (string, error) {
	stored, err := keychain.GetPendingSignupPrepareInput(d.Store)
	if err != nil {
		return "", err
	}
	var record signupInputRecord
	if json.Unmarshal([]byte(stored), &record) != nil || record.Version != 1 || record.AccountID == "" {
		return "", keychain.ErrSecretNotFound
	}
	return record.AccountID, nil
}

// signupInputMatches reports whether the stored record names the staged key
// and was made from this input.
func signupInputMatches(d Deps, publicKey, alias string, recoveryKey []byte, password *memguard.LockedBuffer) bool {
	stored, err := keychain.GetPendingSignupPrepareInput(d.Store)
	if err != nil {
		return false
	}
	var record signupInputRecord
	if json.Unmarshal([]byte(stored), &record) != nil || record.Version != 1 {
		return false
	}
	fingerprint := crypto.AccountKeyFingerprint([]byte(publicKey))
	if record.Fingerprint != fingerprint {
		return false
	}
	salt, saltErr := base64.StdEncoding.DecodeString(record.Salt)
	want, hashErr := base64.StdEncoding.DecodeString(record.Hash)
	if saltErr != nil || hashErr != nil {
		return false
	}
	got := signupInputHash(fingerprint, record.AccountID, alias, recoveryKey, password, salt)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// answerStagedSignup rebuilds the prepare response for the staged signup
// without writing: the same keypair and DEK, freshly wrapped for the password
// and the recovery key of the matching input.
func answerStagedSignup(d Deps, alias string, privateKey, publicKey string, password *memguard.LockedBuffer, recoveryAuthSeed string, wrapKey []byte) proto.BaseResponse {
	accountID, err := readSignupAccountID(d)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "the staged signup account identity is missing")
	}
	signature, response := signWithStagedKey(keychain.StagedAccountKeypair{PrivateKey: privateKey, PublicKey: publicKey}, alias)
	if !response.Success {
		return response
	}
	enrollmentSignature, response := signWithStagedKey(
		keychain.StagedAccountKeypair{PrivateKey: privateKey, PublicKey: publicKey},
		proto.AccountKeyEnrollmentCanonical(accountID, crypto.AccountKeyFingerprint([]byte(publicKey))),
	)
	if !response.Success {
		return response
	}
	privateBuffer := memguard.NewBufferFromBytes([]byte(privateKey))
	secure.WipeString(&privateKey)
	defer privateBuffer.Destroy()
	wrappedKeeper, err := crypto.AESGCMEncryptBase64(wrapKey, privateBuffer.Bytes())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrap staged private key failed")
	}

	deviceWrapped, err := keychain.GetPendingSignupDeviceWrappedDEK(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "the staged signup DEK is missing")
	}
	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	defer secure.Zeroize(deviceKey)
	dek, err := unwrapDeviceWrappedDEK(deviceKey, deviceWrapped)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "the staged signup DEK does not open")
	}
	defer secure.Zeroize(dek)
	passwordWrapped, response := passwordWrapDEK(d, password, dek)
	if !response.Success {
		return response
	}

	return proto.BaseResponse{Success: true, Data: proto.AuthSignupPrepareResponseData{
		AccountID:             accountID,
		EnrollmentSignature:   enrollmentSignature,
		PasswordWrappedDEKB64: passwordWrapped,
		DeviceWrappedDEKB64:   deviceWrapped,
		RecoveryAuthSeed:      recoveryAuthSeed,
		RecoveryWrappedKeeper: wrappedKeeper,
		RecoveryKeyVersion:    recoverykey.Version,
		Signature:             signature,
		PublicKey:             publicKey,
	}}
}

// passwordWrapDEK is the server copy's format: salt(16) || iv(12) || ct.
func passwordWrapDEK(d Deps, password *memguard.LockedBuffer, dek []byte) (string, proto.BaseResponse) {
	salt := make([]byte, dekSaltLength)
	if err := d.FillRandom(salt); err != nil {
		return "", errs.CodeResponse(errs.ErrCodeInternal, "failed to generate salt")
	}
	kek := pbkdf2.Key(password.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)
	iv, ciphertext, err := aesGCMSealSplit(kek, dek)
	if err != nil {
		return "", errs.CodeResponse(errs.ErrCodeCryptoFailure, "password wrap failed")
	}
	out := append(append(salt, iv...), ciphertext...)
	return base64.StdEncoding.EncodeToString(out), proto.BaseResponse{Success: true}
}

// HandleAuthSignupAbort drops the staged signup the server refused.
func HandleAuthSignupAbort(d Deps, req proto.AuthSignupAbortRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	signupStageMu.Lock()
	defer signupStageMu.Unlock()
	discarded, err := keychain.DiscardPendingSignup(d.Store, req.PublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to discard the staged signup")
	}
	return proto.BaseResponse{Success: true, Data: proto.AuthSignupAbortResponseData{Discarded: discarded}}
}
