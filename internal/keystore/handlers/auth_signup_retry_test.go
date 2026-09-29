package handlers

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
)

func stagedSignup(t *testing.T) (Deps, *keychain.MemorySecretStore, proto.AuthSignupPrepareResponseData) {
	t.Helper()
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
	first := HandleAuthSignupPrepare(deps, signupRequest())
	if !first.Success {
		t.Fatalf("first prepare: %s", first.Error)
	}
	return deps, store, first.Data.(proto.AuthSignupPrepareResponseData)
}

// Q8: while a signup key is staged, prepare refuses every request whose
// normalised input differs from the one that staged it, and the keyring keeps
// its bytes. There is no request id to match on: only the input decides.
func TestAuthSignupPrepareRefusesAnotherInputWhileASignupKeyIsStaged(t *testing.T) {
	deps, store, _ := stagedSignup(t)
	staged := store.Snapshot()
	for name, edit := range map[string]func(*proto.AuthSignupPrepareRequest){
		"another recovery key": func(r *proto.AuthSignupPrepareRequest) { r.RecoveryKey = "ZZZZ-EFGH-JKLM-NPQR-STUV-WXYZ" },
		"another password":     func(r *proto.AuthSignupPrepareRequest) { r.Password = "another long enough password" },
		"another alias":        func(r *proto.AuthSignupPrepareRequest) { r.Alias = "bob" },
	} {
		request := signupRequest()
		edit(&request)
		assertRefused(t, HandleAuthSignupPrepare(deps, request), errs.ErrCodeSignupPending, name)
		assertSnapshot(t, store, staged, name)
	}
}

// The same input is an idempotent retry: it answers for the staged key
// instead of minting a new one, and still writes nothing.
func TestAuthSignupPrepareRetryWithTheSameInputAnswersForTheStagedKey(t *testing.T) {
	deps, store, first := stagedSignup(t)
	staged := store.Snapshot()

	retry := signupRequest()
	// The recovery key is compared in its normalised form.
	retry.RecoveryKey = " abcd-efgh-jklm-npqr-stuv-wxyz "
	response := HandleAuthSignupPrepare(deps, retry)
	if !response.Success {
		t.Fatalf("idempotent retry refused: %s (%s)", response.ErrorCode, response.Error)
	}
	assertSnapshot(t, store, staged, "an idempotent retry")
	again := response.Data.(proto.AuthSignupPrepareResponseData)
	if again.PublicKey != first.PublicKey || again.DeviceWrappedDEKB64 != first.DeviceWrappedDEKB64 {
		t.Fatal("the retry answered for another key or DEK than the staged ones")
	}
	if again.AccountID != first.AccountID {
		t.Fatal("the retry changed the staged account ID")
	}
	if again.RecoveryAuthSeed != first.RecoveryAuthSeed {
		t.Fatal("the retry derived another recovery seed")
	}

	publicKey, err := crypto.ParsePublicKey(first.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.StdEncoding.DecodeString(again.Signature)
	if crypto.VerifySignature(publicKey, signupRequest().Alias, signature) != nil {
		t.Fatal("the retry's alias signature is not by the staged key")
	}
	enrollmentSignature, err := base64.StdEncoding.DecodeString(again.EnrollmentSignature)
	if err != nil || crypto.VerifySignature(
		publicKey,
		proto.AccountKeyEnrollmentCanonical(again.AccountID, crypto.AccountKeyFingerprint([]byte(again.PublicKey))),
		enrollmentSignature,
	) != nil {
		t.Fatal("the retry's enrollment signature does not bind the staged account ID and key")
	}
	_, wrapKey, err := recoverykey.Derive([]byte(signupRecoveryKey), signupRequest().Alias, recoverykey.Version)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := crypto.AESGCMDecryptBase64(wrapKey, again.RecoveryWrappedKeeper)
	stagedPrivate, _ := keychain.GetPendingPrivateKey(store)
	if err != nil || string(unwrapped) != stagedPrivate {
		t.Fatal("the retry's recovery-wrapped key is not the staged private key")
	}
	password := memguard.NewBufferFromBytes([]byte(signupRequest().Password))
	defer password.Destroy()
	fromPassword, opened := openPasswordWrappedDEK(again.PasswordWrappedDEKB64, password)
	if !opened.Success {
		t.Fatalf("the retry's password-wrapped DEK does not open: %s", opened.Error)
	}
	fromDevice, err := unwrapDeviceWrappedDEK(bytes.Repeat([]byte{0x44}, 32), first.DeviceWrappedDEKB64)
	if err != nil || !bytes.Equal(fromPassword, fromDevice) {
		t.Fatal("the retry's password-wrapped DEK is not the staged DEK")
	}
}

// The input hash is bound to the staged key: once the pending slot holds
// another key, the old input no longer matches.
func TestAuthSignupPrepareInputHashIsBoundToTheStagedKey(t *testing.T) {
	deps, store, _ := stagedSignup(t)
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPrivateKey(store, other.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPublicKey(store, other.PublicKey); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	assertRefused(t, HandleAuthSignupPrepare(deps, signupRequest()), errs.ErrCodeSignupPending, "a record for another key")
	assertSnapshot(t, store, before, "a record for another key")
}

// A staged key with no input record (a prepare that stopped between staging
// and recording) is refused too: nothing proves the retry is the same signup.
func TestAuthSignupPrepareRefusesAStagedKeyWithoutAnInputRecord(t *testing.T) {
	deps, store, _ := stagedSignup(t)
	if err := store.Delete(config.Service, config.PendingSignupPrepareInput); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	assertRefused(t, HandleAuthSignupPrepare(deps, signupRequest()), errs.ErrCodeSignupPending, "no input record")
	assertSnapshot(t, store, before, "no input record")
}

// The input record never holds the password or the recovery key in a form a
// cheap guess can test.
func TestAuthSignupPrepareInputRecordHoldsNoSecretInput(t *testing.T) {
	_, store, _ := stagedSignup(t)
	record, err := store.Get(config.Service, config.PendingSignupPrepareInput)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{signupRequest().Password, signupRecoveryKey, "ABCDEFGHJKLMNPQRSTUVWXYZ"} {
		if bytes.Contains([]byte(record), []byte(secret)) {
			t.Fatalf("the input record contains %q", secret)
		}
	}
}

// Abort drops the staged signup only when it names the staged public key,
// after the server refused the signup; a new signup can then stage again.
func TestAuthSignupAbortDropsOnlyTheNamedStagedSignup(t *testing.T) {
	deps, store, first := stagedSignup(t)
	staged := store.Snapshot()
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrong := HandleAuthSignupAbort(deps, proto.AuthSignupAbortRequest{PublicKey: other.PublicKey})
	if !wrong.Success || wrong.Data.(proto.AuthSignupAbortResponseData).Discarded {
		t.Fatalf("abort for another key: %+v", wrong)
	}
	assertSnapshot(t, store, staged, "an abort naming another key")

	right := HandleAuthSignupAbort(deps, proto.AuthSignupAbortRequest{PublicKey: first.PublicKey})
	if !right.Success || !right.Data.(proto.AuthSignupAbortResponseData).Discarded {
		t.Fatalf("abort for the staged key: %+v", right)
	}
	for _, slot := range []string{
		config.PendingDragPassKeeperPrivateKey, config.PendingDragPassKeeperPublicKey,
		config.PendingSignupPersonalDEK, config.PendingSignupPrepareInput,
	} {
		if _, err := store.Get(config.Service, slot); err == nil {
			t.Fatalf("%s survived the abort", slot)
		}
	}
	another := signupRequest()
	another.Alias = "bob"
	if response := HandleAuthSignupPrepare(deps, another); !response.Success {
		t.Fatalf("a new signup after the abort: %s", response.Error)
	}
}

// On a registered device the pending slots belong to a key rotation, which a
// signup abort must not touch.
func TestAuthSignupAbortLeavesARegisteredDeviceAlone(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedRegisteredDevice(t, store)
	rotation, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPrivateKey(store, rotation.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPublicKey(store, rotation.PublicKey); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	response := HandleAuthSignupAbort(deps, proto.AuthSignupAbortRequest{PublicKey: rotation.PublicKey})
	if !response.Success || response.Data.(proto.AuthSignupAbortResponseData).Discarded {
		t.Fatalf("abort on a registered device: %+v", response)
	}
	assertSnapshot(t, store, before, "an abort on a registered device")
}

// An RK24 reissue while only a staged key exists is refused with a code that
// tells the App to sign in (which promotes the key) first.
func TestRecoveryKeyReissueWithOnlyAStagedSignupKeyAsksForTheSignIn(t *testing.T) {
	deps, store, _ := stagedSignup(t)
	before := store.Snapshot()
	response := HandleAuthRecoveryReissuePrepare(deps, proto.AuthRecoveryReissuePrepareRequest{
		Alias: signupRequest().Alias, RecoveryKey: "ZZZZ-EFGH-JKLM-NPQR-STUV-WXYZ",
	})
	assertRefused(t, response, errs.ErrCodeAccountKeyStaged, "a reissue with only a staged signup key")
	assertSnapshot(t, store, before, "a refused reissue")
}

// Q9: save_session_code says which stage it promoted, so the App can tell a
// recovery (grants wrapped to the lost key need a re-share) from a signup.
func TestSaveSessionCodeReportsWhichStageItPromoted(t *testing.T) {
	for _, stage := range []string{"recovery", "signup"} {
		device := newPendingDevice(t, stage, false)
		encrypted := serverSessionCode(t, device.staged.PublicKey, "code")
		response := saveSignedSessionCode(device.deps, encrypted)
		if !response.Success {
			t.Fatalf("%s: %s", stage, response.Error)
		}
		if got := response.Data.(proto.SaveSessionCodeResponseData).Promoted; got != stage {
			t.Fatalf("%s: promoted = %q", stage, got)
		}
		repeated := saveSignedSessionCode(device.deps, encrypted)
		if got := repeated.Data.(proto.SaveSessionCodeResponseData).Promoted; got != "active" {
			t.Fatalf("%s: a repeated save reported %q, want active", stage, got)
		}
	}
}

// Promoting the signup key also drops its input record.
func TestSignupPromotionDropsTheInputRecord(t *testing.T) {
	deps, store, first := stagedSignup(t)
	deps.ServerKeyVerifier = exactTokenVerifier{}
	if response := saveSignedSessionCode(deps, serverSessionCode(t, first.PublicKey, "code")); !response.Success {
		t.Fatal(response.Error)
	}
	if _, err := store.Get(config.Service, config.PendingSignupPrepareInput); err == nil {
		t.Fatal("the input record survived the promotion")
	}
}
