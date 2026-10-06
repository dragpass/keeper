package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	stageAlias        = "alice"
	stageRecoveryKey  = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	stageNewRecovery  = "ZYXW-VUTS-RQPN-MLKJ-HGFE-DCBA"
	stageOldSession   = "session-code-before-recovery"
	stageNewSession   = "session-code-after-recovery"
	stageRotatedAtNow = int64(1_000_000)
)

// openTestRecoverySession registers raw PEM bytes with deps's
// RecoverySessions and returns a handle. Auto-closed on test end.
func openTestRecoverySession(t *testing.T, deps Deps, rawPEM string) string {
	t.Helper()
	rawCopy := []byte(rawPEM)
	handle, _, err := deps.RecoverySessions.Open(rawCopy)
	if err != nil {
		t.Fatalf("openTestRecoverySession: %v", err)
	}
	t.Cleanup(func() {
		deps.RecoverySessions.Close(handle)
	})
	return handle
}

// recoveryStage is a device part-way through an RK24 recovery: the account
// key the server holds wrapped under the RK24, and whatever this device
// already had in its keyring.
type recoveryStage struct {
	deps       Deps
	store      *testdouble.MemorySecretStore
	oldKey     trustKey
	wrappedOld string
}

func newRecoveryStage(t *testing.T, withAccount bool) *recoveryStage {
	t.Helper()
	deps, _, store := newTestDeps(t)
	deps.Clock = func() time.Time { return time.Unix(stageRotatedAtNow, 0) }
	old := newTrustKey(t)
	wrapped := wrapUnderStageRK24(t, old.pair.PrivateKey)
	if withAccount {
		// The same device still holds the account: its key, session code,
		// device key and personal DEK must all survive a refused recovery.
		if err := keychain.SavePrivateKey(store, old.pair.PrivateKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SavePublicKey(store, old.pair.PublicKey); err != nil {
			t.Fatal(err)
		}
		if err := keychain.SaveSessionCode(store, stageOldSession); err != nil {
			t.Fatal(err)
		}
		setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
		if err := keychain.SavePersonalDeviceWrappedDEK(store, "personal-dek"); err != nil {
			t.Fatal(err)
		}
	}
	return &recoveryStage{deps: deps, store: store, oldKey: old, wrappedOld: wrapped}
}

func wrapUnderStageRK24(t *testing.T, privateKeyPEM string) string {
	t.Helper()
	_, wrapKey, err := recoverykey.Derive([]byte(stageRecoveryKey), stageAlias, recoverykey.Version)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	defer secure.Zeroize(wrapKey)
	wrapped, err := crypto.AESGCMEncryptBase64(rand.Reader, wrapKey, []byte(privateKeyPEM))
	if err != nil {
		t.Fatalf("wrap old key: %v", err)
	}
	return wrapped
}

func failingVerifier() testdouble.AlwaysFailVerifier {
	return testdouble.AlwaysFailVerifier{Err: errors.New("server signature verification failed: stub")}
}

func (s *recoveryStage) begin(t *testing.T, recoveryKey string) string {
	t.Helper()
	response := HandleAuthRecoveryBegin(s.deps, proto.AuthRecoveryBeginRequest{
		Alias: stageAlias, RecoveryKey: recoveryKey,
	})
	if !response.Success {
		t.Fatalf("begin: %s", response.Error)
	}
	return response.Data.(proto.AuthRecoveryBeginResponseData).EnteredKeyHandle
}

func (s *recoveryStage) prepareRequest(handle string) proto.AuthRecoveryPrepareRequest {
	return proto.AuthRecoveryPrepareRequest{
		AccountID:          statementAccount,
		RotatedAt:          stageRotatedAtNow,
		Alias:              stageAlias,
		EnteredKeyHandle:   handle,
		ChallengeToken:     "server-challenge",
		Signature:          "server-signature",
		WrappedKeeperB64:   s.wrappedOld,
		RecoveryKeyVersion: recoverykey.Version,
		ServerKeyVersion:   1,
		NewRecoveryKey:     stageNewRecovery,
	}
}

func (s *recoveryStage) prepare(t *testing.T) proto.AuthRecoveryPrepareResponseData {
	t.Helper()
	response := HandleAuthRecoveryPrepare(s.deps, s.prepareRequest(s.begin(t, stageRecoveryKey)))
	if !response.Success {
		t.Fatalf("prepare: %s", response.Error)
	}
	data := response.Data.(proto.AuthRecoveryPrepareResponseData)
	t.Cleanup(func() { s.deps.RecoverySessions.Close(data.RecoveryHandle) })
	return data
}

// serverSessionCode is what ariadne returns from /recovery/complete: a fresh
// session code encrypted to the public key it accepted.
func serverSessionCode(t *testing.T, publicKeyPEM, code string) string {
	t.Helper()
	publicKey, err := crypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	encrypted, err := crypto.EncryptData(publicKey, []byte(code))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

func saveSessionCode(deps Deps, encrypted string) proto.BaseResponse {
	return HandleSaveSessionCode(deps, proto.SaveSessionCodeRequest{
		EncryptedSessionCode: encrypted, Signature: "server-signature", ServerKeyVersion: 1,
	})
}

func assertSnapshot(t *testing.T, store *testdouble.MemorySecretStore, want map[string]string, what string) {
	t.Helper()
	if got := store.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed the keyring:\n got %v\nwant %v", what, keys(got), keys(want))
	}
}

func keys(snapshot map[string]string) []string {
	out := make([]string, 0, len(snapshot))
	for key := range snapshot {
		out = append(out, key)
	}
	return out
}

// Until the server accepts the recovery, the new account keypair is staged
// only: login, the session code and the personal DEK keep working with the
// old key. The save that carries the server's acceptance promotes it.
func TestAuthRecoveryKeepsTheActiveKeypairUntilTheServerAccepts(t *testing.T) {
	for _, withAccount := range []bool{true, false} {
		stage := newRecoveryStage(t, withAccount)
		before := stage.store.Snapshot()
		prepared := stage.prepare(t)

		after := stage.store.Snapshot()
		for key, value := range before {
			if after[key] != value {
				t.Fatalf("withAccount=%t: prepare changed %s before the server accepted", withAccount, key)
			}
		}
		staged, err := keychain.GetPendingRecoveryPublicKey(stage.store)
		if err != nil || staged != prepared.NewPublicKey {
			t.Fatalf("withAccount=%t: staged public key = %q, %v", withAccount, staged, err)
		}

		if response := saveSessionCode(stage.deps, serverSessionCode(t, prepared.NewPublicKey, stageNewSession)); !response.Success {
			t.Fatalf("withAccount=%t: save_session_code: %s", withAccount, response.Error)
		}
		if active, _ := keychain.GetPublicKey(stage.store); active != prepared.NewPublicKey {
			t.Fatalf("withAccount=%t: the accepted key was not promoted", withAccount)
		}
		if code, _ := keychain.GetSessionCode(stage.store); code != stageNewSession {
			t.Fatalf("withAccount=%t: session code = %q", withAccount, code)
		}
		if present, _ := keychain.HasPendingRecoveryKeypair(stage.store); present {
			t.Fatalf("withAccount=%t: the staged keypair outlived its promotion", withAccount)
		}
		if withAccount {
			if dek, _ := keychain.GetPersonalDeviceWrappedDEK(stage.store); dek != "personal-dek" {
				t.Fatal("recovery replaced the personal DEK")
			}
		}

		// A retried save (a lost response) is a no-op on the promoted key.
		promoted := stage.store.Snapshot()
		if response := saveSessionCode(stage.deps, serverSessionCode(t, prepared.NewPublicKey, stageNewSession)); !response.Success {
			t.Fatalf("withAccount=%t: repeated save_session_code: %s", withAccount, response.Error)
		}
		assertSnapshot(t, stage.store, promoted, "a repeated save_session_code")
	}
}

// A recovery Keeper refuses before the server is ever asked leaves every
// keyring byte where it was.
func TestAuthRecoveryRefusedLeavesTheKeyringByteIdentical(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*recoveryStage, *proto.AuthRecoveryPrepareRequest)
		entered string
	}{
		{name: "wrong RK24", entered: "BCDE-FGHJ-KLMN-PQRS-TUVW-XYZ2"},
		{name: "server signature rejected", entered: stageRecoveryKey, mutate: func(s *recoveryStage, _ *proto.AuthRecoveryPrepareRequest) {
			s.deps.ServerKeyVerifier = failingVerifier()
		}},
		{name: "rotated_at in the future", entered: stageRecoveryKey, mutate: func(_ *recoveryStage, r *proto.AuthRecoveryPrepareRequest) {
			r.RotatedAt = stageRotatedAtNow + proto.KeyRotationPrepareMaxFutureSeconds + 1
		}},
		{name: "malformed new RK24", entered: stageRecoveryKey, mutate: func(_ *recoveryStage, r *proto.AuthRecoveryPrepareRequest) {
			r.NewRecoveryKey = "not-a-recovery-key"
		}},
		{name: "unreadable wrapped key", entered: stageRecoveryKey, mutate: func(s *recoveryStage, r *proto.AuthRecoveryPrepareRequest) {
			r.WrappedKeeperB64 = wrapUnderStageRK24(t, "not a private key")
		}},
	}
	for _, tc := range cases {
		for _, withAccount := range []bool{true, false} {
			stage := newRecoveryStage(t, withAccount)
			before := stage.store.Snapshot()
			request := stage.prepareRequest(stage.begin(t, tc.entered))
			if tc.mutate != nil {
				tc.mutate(stage, &request)
			}
			if response := HandleAuthRecoveryPrepare(stage.deps, request); response.Success {
				t.Fatalf("%s: prepare accepted", tc.name)
			}
			assertSnapshot(t, stage.store, before, tc.name)
			if stage.deps.RecoverySessions.Size() != 0 {
				t.Fatalf("%s: a refused prepare left the old key open", tc.name)
			}
		}
	}
}

// The server refused the recovery after Keeper prepared it: the abort removes
// exactly what the prepare staged.
func TestAuthRecoveryAbortRestoresTheKeyringByteIdentical(t *testing.T) {
	for _, withAccount := range []bool{true, false} {
		stage := newRecoveryStage(t, withAccount)
		before := stage.store.Snapshot()
		prepared := stage.prepare(t)

		other := newTrustKey(t)
		if response := HandleAuthRecoveryAbort(stage.deps, proto.AuthRecoveryAbortRequest{NewPublicKey: other.pair.PublicKey}); !response.Success ||
			response.Data.(proto.AuthRecoveryAbortResponseData).Discarded {
			t.Fatalf("an abort naming another key discarded the staged recovery: %+v", response)
		}
		response := HandleAuthRecoveryAbort(stage.deps, proto.AuthRecoveryAbortRequest{NewPublicKey: prepared.NewPublicKey})
		if !response.Success || !response.Data.(proto.AuthRecoveryAbortResponseData).Discarded {
			t.Fatalf("abort: %+v", response)
		}
		assertSnapshot(t, stage.store, before, "prepare then abort")
		if again := HandleAuthRecoveryAbort(stage.deps, proto.AuthRecoveryAbortRequest{NewPublicKey: prepared.NewPublicKey}); !again.Success {
			t.Fatalf("a repeated abort failed: %s", again.Error)
		}
	}
}

// A retried prepare replaces only the staged keypair; the server's answer to
// the latest attempt is the one that promotes.
func TestAuthRecoveryRetriedPrepareReplacesOnlyTheStagedKeypair(t *testing.T) {
	stage := newRecoveryStage(t, true)
	before := stage.store.Snapshot()
	first := stage.prepare(t)
	second := stage.prepare(t)
	if first.NewPublicKey == second.NewPublicKey {
		t.Fatal("two prepares produced the same keypair")
	}
	after := stage.store.Snapshot()
	for key, value := range before {
		if after[key] != value {
			t.Fatalf("a retried prepare changed %s", key)
		}
	}
	// The first attempt's key is no longer on this device: its acceptance
	// cannot be completed here and must not promote anything.
	if response := saveSessionCode(stage.deps, serverSessionCode(t, first.NewPublicKey, stageNewSession)); response.Success {
		t.Fatal("a session code for a replaced attempt was accepted")
	}
	assertSnapshot(t, stage.store, after, "a session code for a replaced attempt")
	if response := saveSessionCode(stage.deps, serverSessionCode(t, second.NewPublicKey, stageNewSession)); !response.Success {
		t.Fatalf("save for the latest attempt: %s", response.Error)
	}
	if active, _ := keychain.GetPublicKey(stage.store); active != second.NewPublicKey {
		t.Fatal("the latest attempt was not promoted")
	}
}

// A pending keypair the server did not accept is never promoted by a save
// that opens with another key. Before this, save_session_code promoted any
// signup pending keypair it found.
func TestSaveSessionCodeNeverPromotesAPendingKeyTheServerDidNotAccept(t *testing.T) {
	deps, _, store := newTestDeps(t)
	activePublic, _ := setupHandlerKeyPair(t, store)
	abandonedSignup := newTrustKey(t)
	abandonedRecovery := newTrustKey(t)
	if err := keychain.SavePendingPrivateKey(store, abandonedSignup.pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPublicKey(store, abandonedSignup.pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.StagePendingRecoveryKeypair(store, abandonedRecovery.pair.PrivateKey, abandonedRecovery.pair.PublicKey); err != nil {
		t.Fatal(err)
	}

	if response := saveSessionCode(deps, serverSessionCode(t, activePublic, "login-session")); !response.Success {
		t.Fatalf("save_session_code for the active key: %s", response.Error)
	}
	if active, _ := keychain.GetPublicKey(store); active != activePublic {
		t.Fatal("a pending keypair the server never accepted became active")
	}
	if code, _ := keychain.GetSessionCode(store); code != "login-session" {
		t.Fatalf("session code = %q", code)
	}

	stranger := newTrustKey(t)
	snapshot := store.Snapshot()
	response := saveSessionCode(deps, serverSessionCode(t, stranger.pair.PublicKey, "someone-else"))
	if response.Success {
		t.Fatal("a session code for a key this device does not hold was accepted")
	}
	assertSnapshot(t, store, snapshot, "a session code no local key opens")
}

// Promoting a recovery does not touch the trust records this owner keeps
// about peers: a server token alone never resets pins.
func TestAuthRecoveryPromotionLeavesPeerPinsAlone(t *testing.T) {
	stage := newRecoveryStage(t, true)
	pin := keychain.PeerKeyPin{
		V: keychain.PeerKeyPinVersion, Fingerprint: newTrustKey(t).fingerprint,
		State: keychain.PeerKeyPinStateVerified, FirstSeenAt: 1, LastSeenAt: 1, VerifiedAt: 1,
	}
	peer := "22222222-2222-4222-8222-222222222222"
	if err := keychain.SavePeerKeyPin(stage.store, statementAccount, peer, pin); err != nil {
		t.Fatal(err)
	}
	prepared := stage.prepare(t)
	if response := saveSessionCode(stage.deps, serverSessionCode(t, prepared.NewPublicKey, stageNewSession)); !response.Success {
		t.Fatalf("save_session_code: %s", response.Error)
	}
	got, err := keychain.GetPeerKeyPin(stage.store, statementAccount, peer)
	if err != nil || !reflect.DeepEqual(got, pin) {
		t.Fatalf("pin after recovery = %+v err=%v", got, err)
	}
}

// The App's recovery rewrap wraps to this Keeper's own account key, never to
// a key the caller names, and only once the recovery has been promoted.
func TestDEKRewrapWithOldKeyToSelf(t *testing.T) {
	stage := newRecoveryStage(t, false)
	prepared := stage.prepare(t)
	groupDEK := bytes.Repeat([]byte{0x5a}, 32)
	wrappedForOld, err := crypto.EncryptData(&stage.oldKey.priv.PublicKey, groupDEK)
	if err != nil {
		t.Fatal(err)
	}
	request := proto.DEKRewrapWithOldKeyToSelfRequest{
		ChallengeToken:    "server-challenge",
		Signature:         "server-signature",
		RecoveryHandle:    prepared.RecoveryHandle,
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString(wrappedForOld),
		ServerKeyVersion:  1,
	}

	if response := HandleDEKRewrapWithOldKeyToSelf(stage.deps, request); response.Success {
		t.Fatal("rewrap ran before the server accepted the recovery")
	}

	if response := saveSessionCode(stage.deps, serverSessionCode(t, prepared.NewPublicKey, stageNewSession)); !response.Success {
		t.Fatalf("save_session_code: %s", response.Error)
	}
	response := HandleDEKRewrapWithOldKeyToSelf(stage.deps, request)
	if !response.Success {
		t.Fatalf("rewrap to self: %s", response.Error)
	}
	rewrapped, err := base64.StdEncoding.DecodeString(response.Data.(proto.DEKRewrapWithOldKeyResponseData).NewEncryptedGroupDEK)
	if err != nil {
		t.Fatal(err)
	}
	activePrivate, _ := keychain.GetPrivateKey(stage.store)
	newPrivate, err := crypto.ParsePrivateKey(activePrivate)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := crypto.DecryptData(newPrivate, rewrapped)
	if err != nil || !bytes.Equal(opened, groupDEK) {
		t.Fatalf("the rewrap does not open with the promoted key: %v", err)
	}

	failing := stage.deps
	failing.ServerKeyVerifier = failingVerifier()
	if response := HandleDEKRewrapWithOldKeyToSelf(failing, request); response.Success {
		t.Fatal("rewrap ran without a verified recovery challenge")
	}
}

// A device whose active key is still the key being recovered (nothing was
// promoted) cannot use the rewrap to copy grants onto themselves.
func TestDEKRewrapWithOldKeyToSelfRefusesTheUnrotatedKey(t *testing.T) {
	stage := newRecoveryStage(t, true)
	handle := openTestRecoverySession(t, stage.deps, stage.oldKey.pair.PrivateKey)
	wrapped, err := crypto.EncryptData(&stage.oldKey.priv.PublicKey, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	response := HandleDEKRewrapWithOldKeyToSelf(stage.deps, proto.DEKRewrapWithOldKeyToSelfRequest{
		ChallengeToken: "server-challenge", Signature: "server-signature", RecoveryHandle: handle,
		EncryptedGroupDEK: base64.StdEncoding.EncodeToString(wrapped), ServerKeyVersion: 1,
	})
	if response.Success {
		t.Fatal("rewrap wrapped a grant back to the key being recovered")
	}
}

// A reissue wraps the active key under a new RK24. While a recovery is staged
// the active key may not be the account's key any more, so it is refused.
func TestRecoveryKeyReissueRefusedWhileARecoveryIsStaged(t *testing.T) {
	stage := newRecoveryStage(t, true)
	stage.prepare(t)
	before := stage.store.Snapshot()
	response := HandleAuthRecoveryReissuePrepare(stage.deps, proto.AuthRecoveryReissuePrepareRequest{
		Alias: stageAlias, RecoveryKey: stageNewRecovery,
	})
	assertRefused(t, response, errs.ErrCodeAccountKeyStaged, "a reissue while the recovery is staged")
	assertSnapshot(t, stage.store, before, "a refused reissue")
}
