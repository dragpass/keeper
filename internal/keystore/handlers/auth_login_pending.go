// Sign-in with an account key a signup or RK24 recovery staged, for a device
// whose page was lost after the server accepted the key and before
// save_session_code promoted it (App recovery, "page lost" case). Nothing
// here writes: the key becomes active only when the server's session code
// opens with it (keychain.AcceptSessionCode).

package handlers

import (
	"fmt"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAuthLoginPendingSignAlias signs the login alias payload with every
// staged account key. The server accepts at most the one it holds; a
// signature by a key it does not hold proves nothing to anyone.
func HandleAuthLoginPendingSignAlias(d Deps, req proto.AuthLoginPendingSignAliasRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	staged, err := keychain.StagedAccountKeypairs(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the staged account keys")
	}
	if len(staged) == 0 {
		return errs.CodeResponse(errs.ErrCodeNotFound, "no staged account key on this device")
	}
	timestamp := d.Now().Unix()
	payload := fmt.Sprintf("%s:%d", req.Alias, timestamp)
	candidates := make([]proto.AuthLoginPendingCandidate, 0, len(staged))
	for _, pair := range staged {
		signature, response := signWithStagedKey(pair, payload)
		if !response.Success {
			return response
		}
		candidates = append(candidates, proto.AuthLoginPendingCandidate{
			PublicKeyFingerprint: crypto.AccountKeyFingerprint([]byte(pair.PublicKey)),
			Signature:            signature,
		})
	}
	return proto.BaseResponse{Success: true, Data: proto.AuthLoginPendingSignAliasResponseData{
		Timestamp: timestamp, Candidates: candidates,
	}}
}

// HandleAuthLoginPendingSignChallenge signs a login challenge with the staged
// key the server says the account holds. Both the challenge and the binding
// of the challenge to that key's fingerprint must carry the server signature,
// so an App cannot pick the key; and the password must open the server's
// password-wrapped DEK before anything is signed, as on the normal sign-in,
// so a wrong password never yields a session.
func HandleAuthLoginPendingSignChallenge(d Deps, req proto.AuthLoginPendingSignChallengeRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		secure.WipeString(&req.Password)
		return errs.Response(err)
	}
	passwordBuffer := memguard.NewBufferFromBytes([]byte(req.Password))
	secure.WipeString(&req.Password)
	defer passwordBuffer.Destroy()

	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "pending challenge signing"); !ok {
		return resp
	}
	binding := proto.LoginAccountKeyBinding(req.ChallengeToken, req.AccountKeyFingerprint)
	if ok, resp := verifyServerSig(d, binding, req.AccountKeySignature, req.AccountKeyServerKeyVersion, "pending challenge account key"); !ok {
		return resp
	}

	if active, err := keychain.GetPublicKey(d.Store); err == nil &&
		crypto.AccountKeyFingerprint([]byte(active)) == req.AccountKeyFingerprint {
		return errs.CodeResponse(errs.ErrCodeValidation, "the active key is the account key; sign in with it")
	}
	staged, err := keychain.StagedAccountKeypairs(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the staged account keys")
	}
	var match *keychain.StagedAccountKeypair
	for i := range staged {
		if crypto.AccountKeyFingerprint([]byte(staged[i].PublicKey)) == req.AccountKeyFingerprint {
			match = &staged[i]
			break
		}
	}
	if match == nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "the server's account key is none of the staged keys")
	}

	dek, response := openPasswordWrappedDEK(req.EncryptedDEKB64, passwordBuffer)
	if !response.Success {
		if response.ErrorCode == string(errs.ErrCodeCryptoFailure) {
			return errs.CodeResponse(errs.ErrCodePasswordInvalid, "the password does not open the account DEK")
		}
		return response
	}
	secure.Zeroize(dek)

	signature, response := signWithStagedKey(*match, req.ChallengeToken)
	if !response.Success {
		return response
	}
	return proto.BaseResponse{Success: true, Data: proto.SignChallengeTokenResponseData{Signature: signature}}
}

func signWithStagedKey(pair keychain.StagedAccountKeypair, data string) (string, proto.BaseResponse) {
	keyBuffer := memguard.NewBufferFromBytes([]byte(pair.PrivateKey))
	defer keyBuffer.Destroy()
	signature, err := signDataSecure(keyBuffer, data)
	if err != nil {
		return "", errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to sign with the staged key")
	}
	return signature, proto.BaseResponse{Success: true}
}
