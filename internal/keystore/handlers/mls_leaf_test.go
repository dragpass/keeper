// Tests for HandleMLSLeafDeclare and VerifyLeafDeclaration.
//
// The verifier cases are the rows of design §11 V3 that can be judged without
// MLS: A1 (no declaration), A2 (forged signature), A3 (another account's
// declaration), and A5's `compromise` reason, plus the fingerprint, device_id
// and public key substitutions §5.3 step 5 exists to catch. A4 is the pin state
// machine's and is covered by peer_key_trust_test.go.
package handlers

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	leafTestAccountID = "11111111-1111-4111-8111-111111111111"
	leafTestDeviceID  = "44444444-4444-4444-8444-444444444444"
)

const leafTestNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func leafChallenge(accountID, deviceID string, expiresAt int64) string {
	return "dragpass.mls.leaf.challenge|1|" + accountID + "|" + deviceID + "|" + leafTestNonce + "|" +
		strconv.FormatInt(expiresAt, 10)
}

func leafDeclareRequest(reason string) proto.MLSLeafDeclareRequest {
	now := time.Now().Unix()
	req := proto.MLSLeafDeclareRequest{
		ServerSignature: "any",
		AccountID:       leafTestAccountID,
		DeviceID:        leafTestDeviceID,
		NotBefore:       now,
		NotAfter:        now + proto.MLSLeafMaxValiditySeconds,
		Reason:          reason,
	}
	return withLeafChallenge(req)
}

// withLeafChallenge re-issues the challenge for whatever identity req names,
// so tests that change the identity exercise the key check, not the gate.
func withLeafChallenge(req proto.MLSLeafDeclareRequest) proto.MLSLeafDeclareRequest {
	req.ChallengeToken = leafChallenge(req.AccountID, req.DeviceID, time.Now().Unix()+proto.MLSLeafChallengeTTLSeconds)
	return req
}

func accountPublicKey(t *testing.T, pemText string) *rsa.PublicKey {
	t.Helper()
	pub, err := crypto.ParsePublicKey(pemText)
	if err != nil {
		t.Fatalf("parse account public key: %v", err)
	}
	return pub
}

func declareLeaf(t *testing.T, deps Deps, req proto.MLSLeafDeclareRequest) proto.MLSLeafDeclaration {
	t.Helper()
	resp := HandleMLSLeafDeclare(deps, req)
	if !resp.Success {
		t.Fatalf("mls_leaf_declare(%s) failed: %s", req.Reason, resp.Error)
	}
	return resp.Data.(proto.MLSLeafDeclareResponseData).MLSLeafDeclaration
}

// acceptanceFor is the token ariadne signs for a declaration it stored.
func acceptanceFor(d proto.MLSLeafDeclaration) proto.MLSLeafPromoteRequest {
	return proto.MLSLeafPromoteRequest{
		AcceptanceToken: proto.MLSLeafAcceptedToken(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter),
		ServerSignature: "any",
	}
}

func promoteLeaf(t *testing.T, deps Deps, d proto.MLSLeafDeclaration) proto.MLSLeafPromoteResponseData {
	t.Helper()
	resp := HandleMLSLeafPromote(deps, acceptanceFor(d))
	if !resp.Success {
		t.Fatalf("mls_leaf_promote failed: %s", resp.Error)
	}
	return resp.Data.(proto.MLSLeafPromoteResponseData)
}

// enrollLeaf declares and promotes, the way a device reaches an active leaf.
func enrollLeaf(t *testing.T, deps Deps, req proto.MLSLeafDeclareRequest) proto.MLSLeafDeclaration {
	t.Helper()
	d := declareLeaf(t, deps, req)
	promoteLeaf(t, deps, d)
	return d
}

func storedLeafKey(t *testing.T, store keychain.SecretStore) keychain.MLSLeafKey {
	t.Helper()
	key, found, err := keychain.GetMLSLeafKey(store)
	if err != nil || !found {
		t.Fatalf("stored leaf key: found=%v err=%v", found, err)
	}
	return key
}

func pendingLeafKey(t *testing.T, store keychain.SecretStore) keychain.MLSLeafKey {
	t.Helper()
	key, found, err := keychain.GetMLSLeafPending(store)
	if err != nil || !found {
		t.Fatalf("pending leaf key: found=%v err=%v", found, err)
	}
	return key
}

func leafSlots(t *testing.T, store keychain.SecretStore) [2]string {
	t.Helper()
	var out [2]string
	for i, slot := range []string{config.MLSLeafSignatureKey, config.MLSLeafSignatureKeyPending} {
		v, err := store.Get(config.Service, slot)
		if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
			t.Fatal(err)
		}
		out[i] = v
	}
	return out
}

func leafStatus(t *testing.T, deps Deps) proto.MLSLeafStatusResponseData {
	t.Helper()
	resp := HandleMLSLeafStatus(deps, proto.MLSLeafStatusRequest{})
	if !resp.Success {
		t.Fatalf("mls_leaf_status failed: %s", resp.Error)
	}
	return resp.Data.(proto.MLSLeafStatusResponseData)
}

func TestHandleMLSLeafDeclare_EnrollSignsAVerifiableDeclarationIntoPending(t *testing.T) {
	deps, log, store := newTestDeps(t)
	accountPub, _ := seedActiveKeypairForRotateTest(t, store)

	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	decl := declareLeaf(t, deps, req)

	if err := VerifyLeafDeclaration(decl, accountPublicKey(t, accountPub)); err != nil {
		t.Fatalf("declaration does not verify under the account key: %v", err)
	}
	if decl.AccountID != leafTestAccountID || decl.DeviceID != leafTestDeviceID || decl.Reason != proto.MLSLeafReasonEnroll ||
		decl.NotBefore != req.NotBefore || decl.NotAfter != req.NotAfter {
		t.Fatalf("declaration fields do not echo the request: %+v", decl)
	}
	if _, found, _ := keychain.GetMLSLeafKey(store); found {
		t.Fatal("enroll wrote the active slot before any acceptance")
	}

	key := pendingLeafKey(t, store)
	if decl.SignatureKey != base64.StdEncoding.EncodeToString(key.PublicKey) {
		t.Fatal("declared signature_key is not the pending leaf public key")
	}
	if key.AccountID != leafTestAccountID || key.DeviceID != leafTestDeviceID {
		t.Fatal("pending leaf key does not name the declared account and device")
	}
	secretB64 := base64.StdEncoding.EncodeToString(key.SecretKey)
	seedB64 := base64.StdEncoding.EncodeToString(key.SecretKey[:ed25519.SeedSize])
	for _, leaked := range []string{secretB64, seedB64} {
		if log.Contains(leaked) || strings.Contains(decl.Signature+decl.SignatureKey, leaked) {
			t.Fatal("leaf secret key reached the log or the response")
		}
	}
}

// A pending entry is returned as it is, whatever the retry asks for: the
// declaration does not depend on the challenge, and a retry must not mint.
func TestHandleMLSLeafDeclare_APendingEntryIsReturnedAndNothingIsMinted(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	first := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	before := leafSlots(t, store)

	retries := map[string]func(*proto.MLSLeafDeclareRequest){
		"same request":     func(*proto.MLSLeafDeclareRequest) {},
		"fresh challenge":  func(r *proto.MLSLeafDeclareRequest) { *r = withLeafChallenge(*r) },
		"other window":     func(r *proto.MLSLeafDeclareRequest) { r.NotAfter = r.NotBefore + 3600 },
		"other reason":     func(r *proto.MLSLeafDeclareRequest) { r.Reason = proto.MLSLeafReasonRotate },
		"later not_before": func(r *proto.MLSLeafDeclareRequest) { r.NotBefore += 10 },
	}
	for name, mutate := range retries {
		req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
		mutate(&req)
		if got := declareLeaf(t, deps, req); got != first {
			t.Errorf("%s: returned %+v, want the pending declaration", name, got)
		}
		if leafSlots(t, store) != before {
			t.Fatalf("%s: a retry changed the slots", name)
		}
	}
}

// RSA-PSS signatures are randomized. A retry that re-signed would hand the
// server a second declaration for the same key, which it refuses or, worse,
// takes for a new one. The retry must carry the first signature's bytes.
func TestHandleMLSLeafDeclare_ARetryReturnsTheStoredSignatureBytes(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	var first []byte
	for i := range 3 {
		resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
		if !resp.Success {
			t.Fatalf("declare #%d: %s", i+1, resp.Error)
		}
		encoded, err := json.Marshal(resp.Data)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = encoded
			continue
		}
		if string(encoded) != string(first) {
			t.Fatalf("declare #%d returned different bytes:\n%s\n%s", i+1, encoded, first)
		}
	}
}

// ariadne stops accepting a retried declaration once its not_before is more
// than a day old. The Keeper keeps returning it and reports its window; the
// abort is the caller's call.
func TestHandleMLSLeafDeclare_AStalePendingEntryIsReportedNotAborted(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	staged := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	later := time.Now().Add(48 * time.Hour)
	deps.Clock = func() time.Time { return later }
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.NotBefore, req.NotAfter = later.Unix(), later.Unix()+3600
	req.ChallengeToken = leafChallenge(req.AccountID, req.DeviceID, later.Unix()+proto.MLSLeafChallengeTTLSeconds)
	if got := declareLeaf(t, deps, req); got != staged {
		t.Fatal("a stale pending entry was replaced")
	}
	status := leafStatus(t, deps)
	if !status.HasPending || status.PendingNotBefore != staged.NotBefore || status.PendingNotAfter != staged.NotAfter {
		t.Fatalf("status = %+v, want the stale entry's window", status)
	}
}

func TestHandleMLSLeafDeclare_EnrollWithAnActiveKeyIsRefused(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	before := leafSlots(t, store)

	resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("enroll over an active key = %+v, want validation_error", resp)
	}
	if leafSlots(t, store) != before {
		t.Fatal("a refused enroll changed the slots")
	}
}

func TestHandleMLSLeafDeclare_RotateStagesANewKeyAndPromoteReplacesTheOld(t *testing.T) {
	deps, _, store := newTestDeps(t)
	accountPub, _ := seedActiveKeypairForRotateTest(t, store)

	enrolled := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	oldKey := storedLeafKey(t, store)
	oldSecretB64 := base64.StdEncoding.EncodeToString(oldKey.SecretKey)

	rotated := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))

	if rotated.SignatureKey == enrolled.SignatureKey || rotated.SignatureKeyFingerprint == enrolled.SignatureKeyFingerprint {
		t.Fatal("rotate declared the old key")
	}
	if rotated.Reason != proto.MLSLeafReasonRotate {
		t.Fatalf("reason = %q, want rotate", rotated.Reason)
	}
	if err := VerifyLeafDeclaration(rotated, accountPublicKey(t, accountPub)); err != nil {
		t.Fatalf("rotate declaration does not verify: %v", err)
	}
	if base64.StdEncoding.EncodeToString(storedLeafKey(t, store).PublicKey) != enrolled.SignatureKey {
		t.Fatal("rotate touched the active slot before any acceptance")
	}

	if got := promoteLeaf(t, deps, rotated); !got.Promoted || got.Fingerprint != rotated.SignatureKeyFingerprint {
		t.Fatalf("promote = %+v", got)
	}
	newKey := storedLeafKey(t, store)
	if rotated.SignatureKey != base64.StdEncoding.EncodeToString(newKey.PublicKey) {
		t.Fatal("active key is not the one the rotate declared")
	}
	if _, found, _ := keychain.GetMLSLeafPending(store); found {
		t.Fatal("promote left the pending slot filled")
	}
	for _, raw := range leafSlots(t, store) {
		if strings.Contains(raw, oldSecretB64) {
			t.Fatal("the old leaf secret key survived the rotation")
		}
	}
}

func TestHandleMLSLeafDeclare_RotateWithoutEnrollIsNotFound(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("rotate with no key = %+v, want not_found", resp)
	}
	if leafSlots(t, store) != [2]string{} {
		t.Fatal("a refused rotate stored a key")
	}
}

func TestHandleMLSLeafDeclare_NotAfterInThePastIsRefused(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.NotBefore = time.Now().Unix() - 7200
	req.NotAfter = time.Now().Unix() - 1
	if resp := HandleMLSLeafDeclare(deps, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("expired window = %+v, want validation_error", resp)
	}
	if leafSlots(t, store) != [2]string{} {
		t.Fatal("a refused declare stored a key")
	}
}

func TestHandleMLSLeafDeclare_RefusesToRebindAnotherDevicesKey(t *testing.T) {
	for _, promoted := range []bool{false, true} {
		deps, _, store := newTestDeps(t)
		seedActiveKeypairForRotateTest(t, store)
		declared := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
		if promoted {
			promoteLeaf(t, deps, declared)
		}
		before := leafSlots(t, store)

		for _, reason := range []string{proto.MLSLeafReasonEnroll, proto.MLSLeafReasonRotate} {
			otherDevice := leafDeclareRequest(reason)
			otherDevice.DeviceID = "55555555-5555-4555-8555-555555555555"
			otherAccount := leafDeclareRequest(reason)
			otherAccount.AccountID = "22222222-2222-4222-8222-222222222222"
			for _, req := range []proto.MLSLeafDeclareRequest{otherDevice, otherAccount} {
				if resp := HandleMLSLeafDeclare(deps, withLeafChallenge(req)); resp.Success {
					t.Fatalf("promoted=%t: %s for a different identity succeeded", promoted, reason)
				}
			}
		}
		if leafSlots(t, store) != before {
			t.Fatalf("promoted=%t: a refused request changed the slots", promoted)
		}
	}
}

func TestHandleMLSLeafDeclare_GatesBeforeTouchingTheKey(t *testing.T) {
	t.Run("server signature", func(t *testing.T) {
		deps, _, store := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))
		seedActiveKeypairForRotateTest(t, store)
		if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll)); resp.Success {
			t.Fatal("declare succeeded with a rejected server signature")
		}
		if leafSlots(t, store) != [2]string{} {
			t.Fatal("a key was stored before the server signature verified")
		}
	})
	t.Run("future not_before", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		seedActiveKeypairForRotateTest(t, store)
		req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
		req.NotBefore = time.Now().Unix() + proto.KeyRotationPrepareMaxFutureSeconds + 60
		req.NotAfter = req.NotBefore + 60
		if resp := HandleMLSLeafDeclare(deps, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("future not_before = %+v, want validation_error", resp)
		}
	})
	t.Run("no account key", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll)); resp.Success {
			t.Fatal("declare succeeded without an account keypair")
		}
		if leafSlots(t, store) != [2]string{} {
			t.Fatal("a key was stored with nothing to declare it under")
		}
	})
}

// Every token here carries a valid server signature (the verifier passes); what
// is refused is a token not issued for this declaration. Both slots must come
// through each refusal byte for byte.
func TestHandleMLSLeafDeclare_ChallengeIsBoundToPurposeAndIdentity(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	before := leafSlots(t, store)

	now := time.Now().Unix()
	valid := now + proto.MLSLeafChallengeTTLSeconds
	otherID := "55555555-5555-4555-8555-555555555555"
	refused := map[string]string{
		"rotation challenge":   "rotate-challenge-001",
		"other domain":         "dragpass.keyrotation|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|" + strconv.FormatInt(valid, 10),
		"key package domain":   keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID, valid),
		"version 2":            "dragpass.mls.leaf.challenge|2|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|" + strconv.FormatInt(valid, 10),
		"extra field":          leafChallenge(leafTestAccountID, leafTestDeviceID, valid) + "|x",
		"short nonce":          "dragpass.mls.leaf.challenge|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|abcd|" + strconv.FormatInt(valid, 10),
		"padded expiry":        "dragpass.mls.leaf.challenge|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|0" + strconv.FormatInt(valid, 10),
		"other account":        leafChallenge(otherID, leafTestDeviceID, valid),
		"other device":         leafChallenge(leafTestAccountID, otherID, valid),
		"expired":              leafChallenge(leafTestAccountID, leafTestDeviceID, now-1),
		"expires now":          leafChallenge(leafTestAccountID, leafTestDeviceID, now),
		"issued in the future": leafChallenge(leafTestAccountID, leafTestDeviceID, now+proto.MLSLeafChallengeTTLSeconds+mlsLeafChallengeClockSkewSeconds+60),
	}
	for _, reason := range []string{proto.MLSLeafReasonEnroll, proto.MLSLeafReasonRotate} {
		for name, token := range refused {
			req := leafDeclareRequest(reason)
			req.ChallengeToken = token
			if resp := HandleMLSLeafDeclare(deps, req); resp.Success {
				t.Errorf("%s/%s: accepted", reason, name)
			}
			if leafSlots(t, store) != before {
				t.Fatalf("%s/%s: a keyring slot changed on a refused challenge", reason, name)
			}
		}
	}

	if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate)); !resp.Success {
		t.Fatalf("a correctly formed challenge was refused: %s", resp.Error)
	}
}

func TestHandleMLSLeafDeclare_RefusedChallengeCreatesNoKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.ChallengeToken = leafChallenge(leafTestAccountID, leafTestDeviceID, time.Now().Unix()-1)
	if resp := HandleMLSLeafDeclare(deps, req); resp.Success {
		t.Fatal("expired challenge accepted")
	}
	if leafSlots(t, store) != [2]string{} {
		t.Fatal("a refused challenge created a key")
	}
}

// 0.0.44 stored its active record as v2, with a declaration signed over the
// version 1 canonical. That record is not a key any session uses, and enroll
// replaces it with a new key rather than re-signing the old one.
func TestHandleMLSLeafDeclare_AVersionTwoRecordDoesNotComeBackToLife(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	public, secret, _ := ed25519.GenerateKey(nil)
	legacy, _ := json.Marshal(map[string]any{
		"v": 2, "account_id": leafTestAccountID, "device_id": leafTestDeviceID,
		"secret_key": secret, "public_key": public, "declaration": []byte(`{"v":1}`),
	})
	if err := store.Set(config.Service, config.MLSLeafSignatureKey, string(legacy)); err != nil {
		t.Fatal(err)
	}

	if got := leafStatus(t, deps); got.HasActive || got.HasPending {
		t.Fatalf("status over a v2 record = %+v, want no usable entry", got)
	}
	if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate)); resp.Success {
		t.Fatal("rotate treated a v2 record as a live key")
	}
	fresh := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	if fresh.SignatureKey == base64.StdEncoding.EncodeToString(public) {
		t.Fatal("enroll re-declared the key a v2 record held")
	}
	if key := storedLeafKey(t, store); !key.Usable() || string(key.PublicKey) == string(public) {
		t.Fatal("the v2 record survived the enroll that replaced it")
	}
}

// ────────────────────────────────────────────────────────────────────────
// The two defects the external review reproduced against L1.
// ────────────────────────────────────────────────────────────────────────

// slotBarrier holds every read of the active slot until release is closed,
// and reports the first two reads on reads.
type slotBarrier struct {
	keychain.SecretStore
	reads   chan struct{}
	release chan struct{}
}

func (s *slotBarrier) Get(service, account string) (string, error) {
	value, err := s.SecretStore.Get(service, account)
	if account == config.MLSLeafSignatureKey {
		select {
		case s.reads <- struct{}{}:
		default:
		}
		<-s.release
	}
	return value, err
}

// Replaces the review's TestReviewL1ConcurrentEnrollKeepsOneIdentity. Two
// enrolls race: the first reaches the slot read and is held there. Without the
// lock the second reaches the same read, both see an empty slot and each mints
// a key; with it the second waits, then finds the first one's pending entry.
// Both must return the one key that is stored.
func TestMLSLeafDeclare_ConcurrentEnrollReturnsOneKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	barrier := &slotBarrier{SecretStore: store, reads: make(chan struct{}, 2), release: make(chan struct{})}
	deps.Store = barrier
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)

	results := make(chan proto.BaseResponse, 2)
	for range 2 {
		go func() { results <- HandleMLSLeafDeclare(deps, req) }()
	}
	<-barrier.reads
	// Give the other enroll every chance to reach the read as well. With the
	// lock held it cannot, and this wait is only ever spent.
	select {
	case <-barrier.reads:
	case <-time.After(300 * time.Millisecond):
	}
	close(barrier.release)

	deadline := time.After(10 * time.Second)
	var keys []string
	for range 2 {
		select {
		case resp := <-results:
			if !resp.Success {
				t.Fatalf("enroll failed: %s", resp.Error)
			}
			keys = append(keys, resp.Data.(proto.MLSLeafDeclareResponseData).SignatureKey)
		case <-deadline:
			t.Fatal("concurrent enroll did not finish")
		}
	}
	if keys[0] != keys[1] {
		t.Fatal("concurrent enroll returned two different leaf keys")
	}
	if keys[0] != base64.StdEncoding.EncodeToString(pendingLeafKey(t, store).PublicKey) {
		t.Fatal("the returned key is not the stored one")
	}
}

// Replaces the review's TestReviewL1RotateRetryKeepsDeclaredIdentity, and runs
// its whole sequence: the Keeper mints A, the server accepts A, the response
// is lost, the extension retries. The retry must hand back A — not mint B the
// server will never accept — and the acceptance of A must promote it, so the
// Keeper ends on the key the server holds.
func TestMLSLeafDeclare_RotateRetryAfterALostResponseKeepsKeeperAndServerOnOneKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrolled := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	a := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	serverAccepts := acceptanceFor(a)
	retry := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))

	if retry != a {
		t.Fatal("the retry minted a second key instead of returning the pending one")
	}
	if base64.StdEncoding.EncodeToString(storedLeafKey(t, store).PublicKey) != enrolled.SignatureKey {
		t.Fatal("the active key moved before the server's acceptance arrived")
	}
	if resp := HandleMLSLeafPromote(deps, serverAccepts); !resp.Success {
		t.Fatalf("promote: %s", resp.Error)
	}
	if base64.StdEncoding.EncodeToString(storedLeafKey(t, store).PublicKey) != a.SignatureKey {
		t.Fatal("the Keeper does not hold the key the server accepted")
	}
}

// ────────────────────────────────────────────────────────────────────────
// mls_leaf_promote / mls_leaf_abort / mls_leaf_status
// ────────────────────────────────────────────────────────────────────────

func TestHandleMLSLeafPromote_OnlyAnExactAcceptanceOfThePendingEntryPromotes(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrolled := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	pending := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	before := leafSlots(t, store)

	otherID := "55555555-5555-4555-8555-555555555555"
	tok := func(account, device, fp string, nb, na int64) proto.MLSLeafPromoteRequest {
		return proto.MLSLeafPromoteRequest{
			AcceptanceToken: proto.MLSLeafAcceptedToken(account, device, fp, nb, na),
			ServerSignature: "any",
		}
	}
	p := pending
	refused := map[string]proto.MLSLeafPromoteRequest{
		"other account":     tok("22222222-2222-4222-8222-222222222222", p.DeviceID, p.SignatureKeyFingerprint, p.NotBefore, p.NotAfter),
		"other device":      tok(p.AccountID, otherID, p.SignatureKeyFingerprint, p.NotBefore, p.NotAfter),
		"other fingerprint": tok(p.AccountID, p.DeviceID, strings.Repeat("a", 64), p.NotBefore, p.NotAfter),
		"other not_before":  tok(p.AccountID, p.DeviceID, p.SignatureKeyFingerprint, p.NotBefore-1, p.NotAfter),
		"other not_after":   tok(p.AccountID, p.DeviceID, p.SignatureKeyFingerprint, p.NotBefore, p.NotAfter-1),
		"not a token":       {AcceptanceToken: pending.Canonical(), ServerSignature: "any"},
		"a leaf challenge":  {AcceptanceToken: leafChallenge(p.AccountID, p.DeviceID, time.Now().Unix()+60), ServerSignature: "any"},
	}
	for name, req := range refused {
		if resp := HandleMLSLeafPromote(deps, req); resp.Success {
			t.Errorf("%s: promoted", name)
		}
		if leafSlots(t, store) != before {
			t.Fatalf("%s: a refused promote changed the slots", name)
		}
	}

	failing, _, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))
	failing.Store = store
	if resp := HandleMLSLeafPromote(failing, acceptanceFor(pending)); resp.Success {
		t.Fatal("promote succeeded with a rejected server signature")
	}
	if leafSlots(t, store) != before {
		t.Fatal("a promote with a rejected signature changed the slots")
	}

	if got := promoteLeaf(t, deps, pending); !got.Promoted {
		t.Fatalf("exact acceptance did not promote: %+v", got)
	}
	if base64.StdEncoding.EncodeToString(storedLeafKey(t, store).PublicKey) == enrolled.SignatureKey {
		t.Fatal("promote left the old key active")
	}
}

// A promote whose response was lost is retried with the same token; by then
// that token names the active entry, and the retry succeeds without writing.
func TestHandleMLSLeafPromote_ADuplicatePromoteIsIdempotent(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	decl := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	promoteLeaf(t, deps, decl)
	before := leafSlots(t, store)

	got := promoteLeaf(t, deps, decl)
	if got.Promoted || got.Fingerprint != decl.SignatureKeyFingerprint {
		t.Fatalf("duplicate promote = %+v, want promoted=false for the active key", got)
	}
	if leafSlots(t, store) != before {
		t.Fatal("a duplicate promote wrote")
	}

	// With a newer rotation pending, the old token still names the active
	// entry and must not promote the pending one.
	next := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	if got := promoteLeaf(t, deps, decl); got.Promoted {
		t.Fatal("an acceptance of the active entry promoted the pending one")
	}
	if pendingLeafKey(t, store).PublicKey == nil ||
		base64.StdEncoding.EncodeToString(pendingLeafKey(t, store).PublicKey) != next.SignatureKey {
		t.Fatal("the pending rotation was disturbed")
	}
}

// A crash after the active write and before the pending delete leaves the two
// slots holding the same key. That leftover must not read as a declaration
// still waiting: status does not report it and the next rotate mints.
func TestHandleMLSLeafPromote_AnInterruptedPromoteLeavesNoPhantomPending(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	decl := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	pending := pendingLeafKey(t, store)
	if err := keychain.SaveMLSLeafKey(store, pending); err != nil {
		t.Fatal(err)
	}

	if got := leafStatus(t, deps); !got.HasActive || got.HasPending || got.ActiveFingerprint != decl.SignatureKeyFingerprint {
		t.Fatalf("status after an interrupted promote = %+v", got)
	}
	if got := promoteLeaf(t, deps, decl); got.Promoted {
		t.Fatal("the repeated promote was not treated as a duplicate")
	}
	rotated := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	if rotated.SignatureKey == decl.SignatureKey {
		t.Fatal("the leftover pending entry was returned as a new rotation")
	}
}

func TestHandleMLSLeafAbort_DiscardsOnlyThePendingEntryAndIsIdempotent(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrolled := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	staged := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	active := leafSlots(t, store)[0]

	for i, want := range []bool{true, false} {
		resp := HandleMLSLeafAbort(deps, proto.MLSLeafAbortRequest{})
		if !resp.Success || resp.Data.(proto.MLSLeafAbortResponseData).Aborted != want {
			t.Fatalf("abort #%d = %+v, want aborted=%v", i+1, resp, want)
		}
	}
	if leafSlots(t, store) != [2]string{active, ""} {
		t.Fatal("abort touched the active slot or left the pending one")
	}
	if resp := HandleMLSLeafPromote(deps, acceptanceFor(staged)); resp.Success {
		t.Fatal("an aborted declaration was promoted")
	}
	next := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	if next.SignatureKey == staged.SignatureKey || next.SignatureKey == enrolled.SignatureKey {
		t.Fatal("rotate after abort did not mint a new key")
	}
}

func TestHandleMLSLeafStatus_ReportsFingerprintsAndNoSecret(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	if got := leafStatus(t, deps); got != (proto.MLSLeafStatusResponseData{}) {
		t.Fatalf("empty status = %+v", got)
	}

	enrolled := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	if got := leafStatus(t, deps); got.HasActive || !got.HasPending || got.PendingFingerprint != enrolled.SignatureKeyFingerprint ||
		got.PendingNotBefore != enrolled.NotBefore || got.PendingNotAfter != enrolled.NotAfter {
		t.Fatalf("status with pending only = %+v", got)
	}
	promoteLeaf(t, deps, enrolled)
	rotated := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	got := leafStatus(t, deps)
	want := proto.MLSLeafStatusResponseData{
		HasActive: true, ActiveFingerprint: enrolled.SignatureKeyFingerprint, ActiveNotAfter: enrolled.NotAfter,
		HasPending: true, PendingFingerprint: rotated.SignatureKeyFingerprint,
		PendingNotBefore: rotated.NotBefore, PendingNotAfter: rotated.NotAfter,
	}
	if got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}

	encoded, err := json.Marshal(HandleMLSLeafStatus(deps, proto.MLSLeafStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []keychain.MLSLeafKey{storedLeafKey(t, store), pendingLeafKey(t, store)} {
		for _, secret := range [][]byte{key.SecretKey, key.SecretKey[:ed25519.SeedSize], key.Declaration} {
			if strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(secret)) {
				t.Fatal("status exposed a secret or a stored declaration")
			}
		}
	}
}

// The in-process half of WithMLSLeafLock is a plain sync.Mutex. If any helper
// these handlers call while holding it took it again, the call would never
// return; the deadline turns that hang into a failure.
func TestMLSLeafLifecycle_HoldsTheLockWithoutReentering(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	done := make(chan error, 1)
	go func() {
		steps := []func() proto.BaseResponse{
			func() proto.BaseResponse { return HandleMLSLeafStatus(deps, proto.MLSLeafStatusRequest{}) },
			func() proto.BaseResponse {
				return HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
			},
			func() proto.BaseResponse {
				return HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
			},
			func() proto.BaseResponse {
				pending, _, _ := keychain.GetMLSLeafPending(store)
				decl, _ := storedMLSLeafDeclaration(pending)
				return HandleMLSLeafPromote(deps, acceptanceFor(decl))
			},
			func() proto.BaseResponse {
				return HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
			},
			func() proto.BaseResponse { return HandleMLSLeafAbort(deps, proto.MLSLeafAbortRequest{}) },
			func() proto.BaseResponse { return HandleMLSLeafStatus(deps, proto.MLSLeafStatusRequest{}) },
		}
		for i, step := range steps {
			if resp := step(); !resp.Success {
				done <- errors.New("step " + strconv.Itoa(i) + ": " + resp.Error)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the leaf lifecycle did not finish: a helper re-took the leaf lock")
	}

	// And the lock is free afterwards.
	released := make(chan struct{})
	go func() {
		_ = keychain.WithMLSLeafLock(store, func() error { return nil })
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the leaf lock was left held")
	}
}

func TestResetDeviceIdentity_RemovesBothMLSLeafSlots(t *testing.T) {
	deps, _, store := newResetDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("reset failed: %s", resp.Error)
	}
	names := map[string]bool{}
	for _, name := range clearedList(t, resp) {
		names[name] = true
	}
	if !names[config.MLSLeafSignatureKey] || !names[config.MLSLeafSignatureKeyPending] {
		t.Fatalf("cleared = %v, want both leaf slots", clearedList(t, resp))
	}
	if leafSlots(t, store) != [2]string{} {
		t.Fatal("a leaf slot survived the reset")
	}
}

// ────────────────────────────────────────────────────────────────────────
// VerifyLeafDeclaration
// ────────────────────────────────────────────────────────────────────────

func TestVerifyLeafDeclaration_RefusesEverySubstitution(t *testing.T) {
	deps, _, store := newTestDeps(t)
	accountPubPEM, _ := seedActiveKeypairForRotateTest(t, store)
	accountPub := accountPublicKey(t, accountPubPEM)
	good := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	otherAccount, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub := accountPublicKey(t, otherAccount.PublicKey)

	attackerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerFP, err := crypto.MLSLeafSignatureKeyFingerprint(attackerPub)
	if err != nil {
		t.Fatal(err)
	}

	signedByOther := good
	signedByOther.Signature, err = signWithPEM(otherAccount.PrivateKey, good.Canonical())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		decl proto.MLSLeafDeclaration
		key  *rsa.PublicKey
	}{
		"A1 no declaration":               {proto.MLSLeafDeclaration{}, accountPub},
		"A2 forged signature":             {withSignature(good, base64.StdEncoding.EncodeToString(make([]byte, 256))), accountPub},
		"A2 another account's key signed": {signedByOther, accountPub},
		"A3 another account's decl":       {good, otherPub},
		"account_id swapped":              {withAccount(good, "22222222-2222-4222-8222-222222222222"), accountPub},
		"device_id swapped":               {withDevice(good, "55555555-5555-4555-8555-555555555555"), accountPub},
		"wrong fingerprint":               {withFingerprint(good, attackerFP), accountPub},
		"tampered public key":             {withKey(good, attackerPub), accountPub},
		"tampered key and fingerprint":    {withFingerprint(withKey(good, attackerPub), attackerFP), accountPub},
		"key not 32 bytes":                {withKeyBytes(good, append(attackerPub, 0)), accountPub},
		"A5 compromise reason":            {withReason(good, "compromise"), accountPub},
		"unknown reason":                  {withReason(good, "revoke"), accountPub},
		"rotate relabelled":               {withReason(good, proto.MLSLeafReasonRotate), accountPub},
		"not_before moved":                {withNotBefore(good, good.NotBefore+1), accountPub},
		"not_after moved":                 {withNotAfter(good, good.NotAfter-1), accountPub},
		"no account key":                  {good, nil},
	}
	for name, c := range cases {
		if err := VerifyLeafDeclaration(c.decl, c.key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := VerifyLeafDeclaration(good, accountPub); err != nil {
		t.Fatalf("the untouched declaration stopped verifying: %v", err)
	}
}

func signWithPEM(privatePEM, canonical string) (string, error) {
	priv, err := crypto.ParsePrivateKey(privatePEM)
	if err != nil {
		return "", err
	}
	sig, err := crypto.SignData(priv, canonical)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func withSignature(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.Signature = v
	return d
}

func withAccount(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.AccountID = v
	return d
}

func withDevice(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.DeviceID = v
	return d
}

func withFingerprint(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.SignatureKeyFingerprint = v
	return d
}

func withKey(d proto.MLSLeafDeclaration, v ed25519.PublicKey) proto.MLSLeafDeclaration {
	return withKeyBytes(d, v)
}

func withKeyBytes(d proto.MLSLeafDeclaration, v []byte) proto.MLSLeafDeclaration {
	d.SignatureKey = base64.StdEncoding.EncodeToString(v)
	return d
}

func withReason(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.Reason = v
	return d
}

func withNotBefore(d proto.MLSLeafDeclaration, v int64) proto.MLSLeafDeclaration {
	d.NotBefore = v
	return d
}

func withNotAfter(d proto.MLSLeafDeclaration, v int64) proto.MLSLeafDeclaration {
	d.NotAfter = v
	return d
}

// A signature over the literal ariadne pins must verify here, so a canonical
// the two sides build differently cannot pass both suites.
func TestVerifyLeafDeclaration_GoldenCanonicalRoundTrip(t *testing.T) {
	const golden = "dragpass.mls.leaf|2|11111111-1111-4111-8111-111111111111|44444444-4444-4444-8444-444444444444|66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|1788999000|1791591000|enroll"
	account, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signWithPEM(account.PrivateKey, golden)
	if err != nil {
		t.Fatal(err)
	}
	decl := proto.MLSLeafDeclaration{
		AccountID:               leafTestAccountID,
		DeviceID:                leafTestDeviceID,
		SignatureKey:            base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		SignatureKeyFingerprint: "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
		NotBefore:               1788999000,
		NotAfter:                1791591000,
		Reason:                  proto.MLSLeafReasonEnroll,
		Signature:               signature,
	}
	if err := VerifyLeafDeclaration(decl, accountPublicKey(t, account.PublicKey)); err != nil {
		t.Fatalf("declaration signed over the golden literal does not verify: %v", err)
	}
}
