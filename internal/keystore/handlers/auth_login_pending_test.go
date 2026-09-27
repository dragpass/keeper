package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	pendingAlias     = "alice"
	pendingPassword  = "correct horse battery staple"
	pendingChallenge = "server-challenge-token"
	pendingNow       = int64(1_700_000_000)
)

// exactTokenVerifier stands in for the server key: a signature is valid only
// for the one token it was made for, so a binding signed for one challenge or
// one key does not pass for another.
type exactTokenVerifier struct{}

func serverSigned(token string) string { return "server-sig:" + token }

func (exactTokenVerifier) Verify(token, sig string, _ uint) error {
	if sig != serverSigned(token) {
		return errors.New("server signature verification failed")
	}
	return nil
}

// pendingDevice is a device whose signup or recovery the server accepted but
// whose page was lost before save_session_code: the account key is staged,
// and the server holds its public key.
type pendingDevice struct {
	deps         Deps
	store        *keychain.MemorySecretStore
	staged       *crypto.KeyPair
	encryptedDEK string
}

func stagedFingerprint(pair *crypto.KeyPair) string {
	return crypto.AccountKeyFingerprint([]byte(pair.PublicKey))
}

func passwordWrappedDEK(t *testing.T, password string) string {
	t.Helper()
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x31}, 32))
	response := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: password})
	if !response.Success {
		t.Fatalf("password-wrapped DEK: %s", response.Error)
	}
	return response.Data.(proto.DEKGenerateAndWrapDualResponseData).PasswordWrappedDEKB64
}

func newPendingDevice(t *testing.T, stage string, withActive bool) *pendingDevice {
	t.Helper()
	deps, _, store := newTestDeps(t)
	deps.ServerKeyVerifier = exactTokenVerifier{}
	deps.Clock = func() time.Time { return time.Unix(pendingNow, 0) }
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
	if withActive {
		active, err := crypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePrivateKey(store, active.PrivateKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePublicKey(store, active.PublicKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SaveSessionCode(store, "session-code-of-the-old-key"); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePersonalDeviceWrappedDEK(store, "personal-dek"); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	switch stage {
	case "recovery":
		if err := keychain.StagePendingRecoveryKeypair(store, staged.PrivateKey, staged.PublicKey); err != nil {
			t.Fatal(err)
		}
	case "signup":
		if err := keychain.SavePendingPrivateKey(store, staged.PrivateKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePendingPublicKey(store, staged.PublicKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePendingSignupDeviceWrappedDEK(store, "pending-signup-dek"); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown stage %q", stage)
	}
	return &pendingDevice{deps: deps, store: store, staged: staged, encryptedDEK: passwordWrappedDEK(t, pendingPassword)}
}

// challengeRequest is the login/request answer for the account whose key has
// the given fingerprint, as ariadne signs it in App mode.
func (p *pendingDevice) challengeRequest(fingerprint string) proto.AuthLoginPendingSignChallengeRequest {
	return proto.AuthLoginPendingSignChallengeRequest{
		ChallengeToken:             pendingChallenge,
		Signature:                  serverSigned(pendingChallenge),
		ServerKeyVersion:           1,
		AccountKeyFingerprint:      fingerprint,
		AccountKeySignature:        serverSigned(proto.LoginAccountKeyBinding(pendingChallenge, fingerprint)),
		AccountKeyServerKeyVersion: 1,
		Password:                   pendingPassword,
		EncryptedDEKB64:            p.encryptedDEK,
	}
}

func verifiesWith(t *testing.T, publicKeyPEM, data, signature string) bool {
	t.Helper()
	publicKey, err := crypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.VerifySignature(publicKey, data, raw) == nil
}

func assertRefused(t *testing.T, response proto.BaseResponse, code errs.ErrorCode, what string) {
	t.Helper()
	if response.Success || response.ErrorCode != string(code) {
		t.Fatalf("%s = success %t code %q (%s); want %s", what, response.Success, response.ErrorCode, response.Error, code)
	}
}

func TestPendingLoginSignsTheAliasWithEachStagedKeyAndWritesNothing(t *testing.T) {
	for _, stage := range []string{"recovery", "signup"} {
		for _, withActive := range []bool{false, true} {
			name := fmt.Sprintf("%s/active=%t", stage, withActive)
			device := newPendingDevice(t, stage, withActive)
			before := device.store.Snapshot()

			response := HandleAuthLoginPendingSignAlias(device.deps, proto.AuthLoginPendingSignAliasRequest{Alias: pendingAlias})
			if !response.Success {
				t.Fatalf("%s: %s", name, response.Error)
			}
			data := response.Data.(proto.AuthLoginPendingSignAliasResponseData)
			if data.Timestamp != pendingNow || len(data.Candidates) != 1 {
				t.Fatalf("%s: timestamp %d, %d candidates", name, data.Timestamp, len(data.Candidates))
			}
			candidate := data.Candidates[0]
			if candidate.PublicKeyFingerprint != stagedFingerprint(device.staged) {
				t.Fatalf("%s: candidate fingerprint is not the staged key's", name)
			}
			payload := fmt.Sprintf("%s:%d", pendingAlias, pendingNow)
			if !verifiesWith(t, device.staged.PublicKey, payload, candidate.Signature) {
				t.Fatalf("%s: alias signature is not the staged key's", name)
			}
			assertSnapshot(t, device.store, before, name+": pending alias signing")
		}
	}
}

// The staged recovery key comes first: a recovery is always the later of the
// two on one device (signup refuses a registered device).
func TestPendingLoginOffersTheRecoveryKeyBeforeTheSignupKey(t *testing.T) {
	device := newPendingDevice(t, "signup", false)
	recovery, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.StagePendingRecoveryKeypair(device.store, recovery.PrivateKey, recovery.PublicKey); err != nil {
		t.Fatal(err)
	}
	response := HandleAuthLoginPendingSignAlias(device.deps, proto.AuthLoginPendingSignAliasRequest{Alias: pendingAlias})
	data := response.Data.(proto.AuthLoginPendingSignAliasResponseData)
	if len(data.Candidates) != 2 ||
		data.Candidates[0].PublicKeyFingerprint != stagedFingerprint(recovery) ||
		data.Candidates[1].PublicKeyFingerprint != stagedFingerprint(device.staged) {
		t.Fatalf("candidates = %+v", data.Candidates)
	}
}

func TestPendingLoginAliasIsRefusedWithoutAStagedKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedRegisteredDevice(t, store)
	before := store.Snapshot()
	response := HandleAuthLoginPendingSignAlias(deps, proto.AuthLoginPendingSignAliasRequest{Alias: pendingAlias})
	assertRefused(t, response, errs.ErrCodeNotFound, "pending alias without a staged key")
	assertSnapshot(t, store, before, "a refused pending alias signing")
	assertRefused(t, HandleAuthLoginPendingSignAlias(deps, proto.AuthLoginPendingSignAliasRequest{}),
		errs.ErrCodeValidation, "pending alias without an alias")
}

func TestPendingLoginSignsTheChallengeOnlyForTheKeyTheServerNamed(t *testing.T) {
	for _, stage := range []string{"recovery", "signup"} {
		for _, withActive := range []bool{false, true} {
			name := fmt.Sprintf("%s/active=%t", stage, withActive)
			device := newPendingDevice(t, stage, withActive)
			before := device.store.Snapshot()

			response := HandleAuthLoginPendingSignChallenge(device.deps, device.challengeRequest(stagedFingerprint(device.staged)))
			if !response.Success {
				t.Fatalf("%s: %s", name, response.Error)
			}
			signature := response.Data.(proto.SignChallengeTokenResponseData).Signature
			if !verifiesWith(t, device.staged.PublicKey, pendingChallenge, signature) {
				t.Fatalf("%s: challenge signature is not the staged key's", name)
			}
			// Signing is not promotion: only save_session_code promotes.
			assertSnapshot(t, device.store, before, name+": pending challenge signing")
		}
	}
}

// Every refusal ends before anything is signed and leaves the keyring as it
// was: a server key that is none of the staged keys, the active key, a wrong
// password, and any server signature that does not cover what it claims.
func TestPendingLoginChallengeRefusalsLeaveTheKeyringUnchanged(t *testing.T) {
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"recovery", "signup"} {
		device := newPendingDevice(t, stage, true)
		activePublic, err := keychain.GetPublicKey(device.store)
		if err != nil {
			t.Fatal(err)
		}
		before := device.store.Snapshot()
		staged := stagedFingerprint(device.staged)
		cases := map[string]struct {
			edit func(*proto.AuthLoginPendingSignChallengeRequest)
			code errs.ErrorCode
		}{
			"server key matches no local key": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				*r = device.challengeRequest(stagedFingerprint(other))
			}, errs.ErrCodeNotFound},
			"server key is the active key": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				*r = device.challengeRequest(crypto.AccountKeyFingerprint([]byte(activePublic)))
			}, errs.ErrCodeValidation},
			"wrong password": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.Password = "not the password at all"
			}, errs.ErrCodePasswordInvalid},
			"challenge not server-signed": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.Signature = serverSigned("another-challenge")
			}, errs.ErrCodeCryptoFailure},
			"binding claimed by the App, not signed": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.AccountKeySignature = "app-asserted"
			}, errs.ErrCodeCryptoFailure},
			"binding signed for another challenge": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.AccountKeySignature = serverSigned(proto.LoginAccountKeyBinding("another-challenge", staged))
			}, errs.ErrCodeCryptoFailure},
			"binding signed for another key": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.AccountKeySignature = serverSigned(proto.LoginAccountKeyBinding(pendingChallenge, stagedFingerprint(other)))
			}, errs.ErrCodeCryptoFailure},
			"malformed fingerprint": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.AccountKeyFingerprint = "ABC"
			}, errs.ErrCodeValidation},
			"missing password": {func(r *proto.AuthLoginPendingSignChallengeRequest) {
				r.Password = ""
			}, errs.ErrCodeValidation},
		}
		for name, c := range cases {
			request := device.challengeRequest(staged)
			c.edit(&request)
			assertRefused(t, HandleAuthLoginPendingSignChallenge(device.deps, request), c.code, stage+": "+name)
			assertSnapshot(t, device.store, before, stage+": "+name)
		}
	}
}

// After the pending sign-in the server's session code is what promotes: it
// opens only with the key the server holds. A session code for any other key
// changes nothing, and a repeated save changes nothing more.
// saveSignedSessionCode is what the App sends after POST /account/session-code:
// the session code the server encrypted to the account key, signed.
func saveSignedSessionCode(deps Deps, encrypted string) proto.BaseResponse {
	return HandleSaveSessionCode(deps, proto.SaveSessionCodeRequest{
		EncryptedSessionCode: encrypted, Signature: serverSigned(encrypted), ServerKeyVersion: 1,
	})
}

func TestPendingLoginPromotesOnlyThroughTheServersSessionCode(t *testing.T) {
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"recovery", "signup"} {
		device := newPendingDevice(t, stage, true)
		before := device.store.Snapshot()
		foreign := saveSignedSessionCode(device.deps, serverSessionCode(t, other.PublicKey, "someone-elses-code"))
		assertRefused(t, foreign, errs.ErrCodeCryptoFailure, stage+": a session code for another key")
		assertSnapshot(t, device.store, before, stage+": a session code for another key")

		if response := saveSignedSessionCode(device.deps, serverSessionCode(t, device.staged.PublicKey, "reissued-code")); !response.Success {
			t.Fatalf("%s: save_session_code: %s", stage, response.Error)
		}
		if active, _ := keychain.GetPublicKey(device.store); active != device.staged.PublicKey {
			t.Fatalf("%s: the staged key the server holds was not promoted", stage)
		}
		promoted := device.store.Snapshot()
		if response := saveSignedSessionCode(device.deps, serverSessionCode(t, device.staged.PublicKey, "reissued-code")); !response.Success {
			t.Fatalf("%s: repeated save_session_code: %s", stage, response.Error)
		}
		assertSnapshot(t, device.store, promoted, stage+": a repeated save_session_code")

		// With nothing staged the normal paths apply again: the pending
		// sign-in refuses and an RK24 reissue wraps the promoted key.
		assertRefused(t, HandleAuthLoginPendingSignAlias(device.deps, proto.AuthLoginPendingSignAliasRequest{Alias: pendingAlias}),
			errs.ErrCodeNotFound, stage+": pending alias after promotion")
		reissue := HandleAuthRecoveryReissuePrepare(device.deps, proto.AuthRecoveryReissuePrepareRequest{
			Alias: pendingAlias, RecoveryKey: stageNewRecovery,
		})
		if !reissue.Success {
			t.Fatalf("%s: reissue after promotion: %s", stage, reissue.Error)
		}
	}
}
