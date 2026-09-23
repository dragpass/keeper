// Tests for HandleMLSKeyPackageGenerate. The challenge gate runs in every
// build; the KeyPackages themselves only where the MLS library is linked, and
// the default build answers CHAT_MLS_CAPABILITY_REQUIRED instead.
package handlers

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func keyPackageChallengeToken(accountID, deviceID string, expiresAt int64) string {
	return "dragpass.mls.keypackage.challenge|1|" + accountID + "|" + deviceID + "|" + leafTestNonce + "|" +
		strconv.FormatInt(expiresAt, 10)
}

// newKeyPackageFixture is the chat state fixture on the wall clock: mls-rs
// stamps KeyPackage lifetimes from the wall clock, and a declaration window
// on the fixture's 2023 clock would have ended long before it.
func newKeyPackageFixture(t *testing.T) *chatStateFixture {
	t.Helper()
	f := newChatStateFixture(t)
	f.clock.unix = time.Now().Unix()
	return f
}

func (f *chatStateFixture) signed(t *testing.T, token string) (string, uint) {
	t.Helper()
	sig, err := crypto.SignData(f.key, token)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig), msgServerKeyVersion
}

// keyPackageRequest is a correctly signed request for the fixture's leaf
// identity; token overrides the challenge when non-empty.
func (f *chatStateFixture) keyPackageRequest(t *testing.T, count int, token string) proto.MLSKeyPackageGenerateRequest {
	t.Helper()
	if token == "" {
		token = keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID,
			f.clock.now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds)
	}
	sig, version := f.signed(t, token)
	return proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: token, ServerSignature: sig, ServerKeyVersion: version,
		AccountID: leafTestAccountID, DeviceID: leafTestDeviceID, Count: count,
	}
}

// enrollAccount gives the fixture's keyring an account keypair and an active
// leaf declared for accountID, through a challenge and an acceptance the
// fixture's server key signed. notAfter of zero means the full window.
func (f *chatStateFixture) enrollAccount(t *testing.T, accountID string, notAfter int64) proto.MLSLeafDeclaration {
	t.Helper()
	seedActiveKeypairForRotateTest(t, f.deps.Store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.AccountID = accountID
	req.NotBefore = f.clock.now().Unix()
	req.NotAfter = req.NotBefore + proto.MLSLeafMaxValiditySeconds
	if notAfter != 0 {
		req.NotAfter = notAfter
	}
	req.ChallengeToken = leafChallenge(accountID, req.DeviceID, f.clock.now().Unix()+proto.MLSLeafChallengeTTLSeconds)
	req.ServerSignature, req.ServerKeyVersion = f.signed(t, req.ChallengeToken)
	decl := declareLeaf(t, f.deps, req)
	accept := acceptanceFor(decl)
	accept.ServerSignature, accept.ServerKeyVersion = f.signed(t, accept.AcceptanceToken)
	if resp := HandleMLSLeafPromote(f.deps, accept); !resp.Success {
		t.Fatalf("promote: %s", resp.Error)
	}
	return decl
}

func (f *chatStateFixture) poolSize(t *testing.T, accountID string) int {
	t.Helper()
	store, err := chatstate.Open(f.deps.Store, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	n, err := store.KeyPackagePoolSize(f.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMLSKeyPackageGenerate_TheGateRunsFirst(t *testing.T) {
	f := newKeyPackageFixture(t)
	req := f.keyPackageRequest(t, 1, "")
	req.ServerSignature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
	if resp := HandleMLSKeyPackageGenerate(f.deps, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("unsigned challenge: %+v", resp)
	}
	for _, count := range []int{0, proto.MLSKeyPackageGenerateMaxCount + 1} {
		if resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, count, "")); resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("count %d: %q", count, resp.ErrorCode)
		}
	}
	f.assertStateRootAbsent(t)
}

// Every token here is correctly signed; what is refused is a token not issued
// for this purpose, account and device, or not current. The leaf declaration
// challenge is the case that matters most: the two gates must not open each
// other (the reverse is in TestHandleMLSLeafDeclare_ChallengeIsBoundToPurposeAndIdentity).
func TestMLSKeyPackageGenerate_TheChallengeIsBoundToPurposeAndIdentity(t *testing.T) {
	f := newKeyPackageFixture(t)
	now := f.clock.now().Unix()
	valid := now + proto.MLSKeyPackageChallengeTTLSeconds
	otherID := "55555555-5555-4555-8555-555555555555"
	refused := map[string]string{
		"leaf challenge":       leafChallenge(leafTestAccountID, leafTestDeviceID, valid),
		"version 2":            "dragpass.mls.keypackage.challenge|2|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|" + strconv.FormatInt(valid, 10),
		"extra field":          keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID, valid) + "|x",
		"missing field":        "dragpass.mls.keypackage.challenge|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + strconv.FormatInt(valid, 10),
		"other account":        keyPackageChallengeToken(otherID, leafTestDeviceID, valid),
		"other device":         keyPackageChallengeToken(leafTestAccountID, otherID, valid),
		"expired":              keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID, now-1),
		"expires now":          keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID, now),
		"issued in the future": keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID, now+proto.MLSKeyPackageChallengeTTLSeconds+mlsLeafChallengeClockSkewSeconds+60),
		"a permit canonical":   proto.ChatStatePermitCanonical(f.unsignedPermit()),
	}
	for name, token := range refused {
		resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 1, token))
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Errorf("%s: %+v", name, resp)
		}
	}
	f.assertStateRootAbsent(t)
}

// A device with no conversation at all can make the KeyPackages it needs to be
// added to its first one, and their private keys are kept.
func TestMLSKeyPackageGenerate_ANewDeviceGetsKeyPackagesAndTheirKeysAreKept(t *testing.T) {
	f := newKeyPackageFixture(t)
	decl := f.enrollAccount(t, leafTestAccountID, 0)

	resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 3, ""))
	if !mls.Available() {
		if resp.ErrorCode != proto.ChatMLSErrorCodeCapabilityRequired {
			t.Fatalf("without the library: %+v", resp)
		}
		return
	}
	if !resp.Success {
		t.Fatalf("generate: %s", resp.Error)
	}
	data := resp.Data.(proto.MLSKeyPackageGenerateResponseData)
	if len(data.KeyPackages) != 3 {
		t.Fatalf("%d key packages", len(data.KeyPackages))
	}
	for _, kp := range data.KeyPackages {
		raw, err := base64.StdEncoding.DecodeString(kp.KeyPackageB64)
		if err != nil || len(raw) == 0 || len(raw) > mls.MaxKeyPackageBytes {
			t.Fatalf("key package of %d bytes, %v", len(raw), err)
		}
		if kp.NotAfter <= uint64(f.clock.now().Unix()) || kp.NotAfter > uint64(decl.NotAfter) {
			t.Fatalf("not_after %d outside (now, declaration not_after %d]", kp.NotAfter, decl.NotAfter)
		}
	}
	if n := f.poolSize(t, leafTestAccountID); n != 3 {
		t.Fatalf("pool holds %d entries, want 3", n)
	}
}

// A KeyPackage cannot outlive the declaration it embeds: a declaration that
// ends in a day clamps every KeyPackage to that day, and the response says so.
func TestMLSKeyPackageGenerate_ClampsToTheDeclarationAndRefusesAnExpiredOne(t *testing.T) {
	if !mls.Available() {
		t.Skip("the declaration check runs after the library check")
	}
	f := newKeyPackageFixture(t)
	end := f.clock.now().Unix() + 86400
	f.enrollAccount(t, leafTestAccountID, end)

	resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 2, ""))
	if !resp.Success {
		t.Fatalf("generate: %s", resp.Error)
	}
	for _, kp := range resp.Data.(proto.MLSKeyPackageGenerateResponseData).KeyPackages {
		if kp.NotAfter > uint64(end) || kp.NotAfter+5 < uint64(end) {
			t.Fatalf("not_after %d, want the declaration's %d", kp.NotAfter, end)
		}
	}

	f.clock.unix = end
	resp = HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 1, ""))
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("an expired declaration: %+v", resp)
	}
	if n := f.poolSize(t, leafTestAccountID); n != 0 {
		t.Fatalf("pool holds %d entries after the declaration expired", n)
	}
}

func TestMLSKeyPackageGenerate_NeedsAnActiveLeafForTheChallengesIdentity(t *testing.T) {
	if !mls.Available() {
		t.Skip("the leaf checks run after the library check")
	}
	f := newKeyPackageFixture(t)
	if resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 1, "")); resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("no leaf: %+v", resp)
	}

	// A pending leaf is not one KeyPackages may carry.
	seedActiveKeypairForRotateTest(t, f.deps.Store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.ServerSignature, req.ServerKeyVersion = f.signed(t, req.ChallengeToken)
	declareLeaf(t, f.deps, req)
	if resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 1, "")); resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("pending leaf only: %+v", resp)
	}

	// A challenge for one account must not mint KeyPackages for another
	// account's leaf.
	g := newKeyPackageFixture(t)
	g.enrollAccount(t, "22222222-2222-4222-8222-222222222222", 0)
	if resp := HandleMLSKeyPackageGenerate(g.deps, g.keyPackageRequest(t, 1, "")); resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("another account's leaf: %+v", resp)
	}
}

// stageRotation declares a rotation, leaving the new key pending, and returns
// the signed acceptance that would promote it.
func (f *chatStateFixture) stageRotation(t *testing.T) (proto.MLSLeafDeclaration, proto.MLSLeafPromoteRequest) {
	t.Helper()
	req := leafDeclareRequest(proto.MLSLeafReasonRotate)
	req.NotBefore = f.clock.now().Unix()
	req.NotAfter = req.NotBefore + proto.MLSLeafMaxValiditySeconds
	req.ChallengeToken = leafChallenge(req.AccountID, req.DeviceID, f.clock.now().Unix()+proto.MLSLeafChallengeTTLSeconds)
	req.ServerSignature, req.ServerKeyVersion = f.signed(t, req.ChallengeToken)
	decl := declareLeaf(t, f.deps, req)
	accept := acceptanceFor(decl)
	accept.ServerSignature, accept.ServerKeyVersion = f.signed(t, accept.AcceptanceToken)
	return decl, accept
}

func activeLeafFingerprint(store keychain.SecretStore) string {
	key, found, err := keychain.GetMLSLeafKey(store)
	defer func() { wipeMLSLeafSlots(&key) }()
	if err != nil || !found {
		return ""
	}
	decl, err := storedMLSLeafDeclaration(key)
	if err != nil {
		return ""
	}
	return decl.SignatureKeyFingerprint
}

// assertKeyPackagesAreFor checks that data names want's leaf and that every
// KeyPackage carries want's raw signature key and want's declaration, and not
// other's key. bytes.Contains is how the mls package's own tests find the
// leaf key in a KeyPackage; a random 32-byte key does not occur by accident.
func assertKeyPackagesAreFor(t *testing.T, data proto.MLSKeyPackageGenerateResponseData, want, other proto.MLSLeafDeclaration) {
	t.Helper()
	if data.LeafSignatureKeyFingerprint != want.SignatureKeyFingerprint {
		t.Fatalf("response names leaf %s, want %s", data.LeafSignatureKeyFingerprint, want.SignatureKeyFingerprint)
	}
	wantKey, _ := base64.StdEncoding.DecodeString(want.SignatureKey)
	otherKey, _ := base64.StdEncoding.DecodeString(other.SignatureKey)
	if fp, err := crypto.MLSLeafSignatureKeyFingerprint(wantKey); err != nil || fp != data.LeafSignatureKeyFingerprint {
		t.Fatal("the returned fingerprint is not the fingerprint of the declared key")
	}
	if len(data.KeyPackages) == 0 {
		t.Fatal("no key packages")
	}
	for i, kp := range data.KeyPackages {
		raw, err := base64.StdEncoding.DecodeString(kp.KeyPackageB64)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, wantKey) || !bytes.Contains(raw, []byte(want.SignatureKeyFingerprint)) {
			t.Fatalf("key package %d does not carry the leaf the response names", i)
		}
		if len(otherKey) != 0 && bytes.Contains(raw, otherKey) {
			t.Fatalf("key package %d carries the other leaf's key", i)
		}
	}
}

func TestMLSKeyPackageGenerate_TheFingerprintNamesTheKeyEveryPackageEmbeds(t *testing.T) {
	if !mls.Available() {
		t.Skip("key packages need the MLS library")
	}
	f := newKeyPackageFixture(t)
	first := f.enrollAccount(t, leafTestAccountID, 0)

	resp := HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 4, ""))
	if !resp.Success {
		t.Fatalf("generate: %s", resp.Error)
	}
	assertKeyPackagesAreFor(t, resp.Data.(proto.MLSKeyPackageGenerateResponseData), first, proto.MLSLeafDeclaration{})

	// A pending rotation changes nothing; its promote does.
	second, accept := f.stageRotation(t)
	resp = HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 2, ""))
	if !resp.Success {
		t.Fatalf("generate with a rotation pending: %s", resp.Error)
	}
	assertKeyPackagesAreFor(t, resp.Data.(proto.MLSKeyPackageGenerateResponseData), first, second)
	if promoted := HandleMLSLeafPromote(f.deps, accept); !promoted.Success {
		t.Fatalf("promote: %s", promoted.Error)
	}
	resp = HandleMLSKeyPackageGenerate(f.deps, f.keyPackageRequest(t, 2, ""))
	if !resp.Success {
		t.Fatalf("generate after the promote: %s", resp.Error)
	}
	assertKeyPackagesAreFor(t, resp.Data.(proto.MLSKeyPackageGenerateResponseData), second, first)
}

// poolWriteBarrier parks the first read of a chat state seal key: the step a
// generation reaches after building its KeyPackages and before writing their
// private keys to the pool. On release it records which leaf is active as the
// generation goes on to that write.
type poolWriteBarrier struct {
	keychain.SecretStore
	armed          atomic.Bool
	reached        chan struct{}
	release        chan struct{}
	activeAtResume string
}

func (b *poolWriteBarrier) Get(service, account string) (string, error) {
	if strings.HasPrefix(account, config.ChatStateSealKeyPrefix) && b.armed.CompareAndSwap(true, false) {
		close(b.reached)
		<-b.release
		b.activeAtResume = activeLeafFingerprint(b.SecretStore)
	}
	return b.SecretStore.Get(service, account)
}

// The externally reported race. A generation reads leaf A and is parked before
// its pool write; a promote of B is started meanwhile. Without the leaf lock
// the promote lands during the park, and the pool is written, and the
// response returned, for a leaf that is no longer active. With it the promote
// waits, and the KeyPackages are for the leaf that was active from the read
// to the write.
func TestMLSKeyPackageGenerate_APromoteCannotLandBetweenTheReadAndThePoolWrite(t *testing.T) {
	if !mls.Available() {
		t.Skip("key packages need the MLS library")
	}
	f := newKeyPackageFixture(t)
	first := f.enrollAccount(t, leafTestAccountID, 0)
	second, accept := f.stageRotation(t)

	barrier := &poolWriteBarrier{SecretStore: f.deps.Store, reached: make(chan struct{}), release: make(chan struct{})}
	barrier.armed.Store(true)
	deps := f.deps
	deps.Store = barrier
	req := f.keyPackageRequest(t, 3, "")

	generated := make(chan proto.BaseResponse, 1)
	go func() { generated <- HandleMLSKeyPackageGenerate(deps, req) }()
	select {
	case <-barrier.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the generation never reached its pool write")
	}

	promoted := make(chan proto.BaseResponse, 1)
	go func() { promoted <- HandleMLSLeafPromote(deps, accept) }()
	// With the lock the promote cannot finish while the generation holds it,
	// and this wait is only ever spent. Without it the promote is done well
	// inside.
	select {
	case resp := <-promoted:
		promoted <- resp
	case <-time.After(300 * time.Millisecond):
	}
	close(barrier.release)

	deadline := time.After(10 * time.Second)
	var gen, prom proto.BaseResponse
	select {
	case gen = <-generated:
	case <-deadline:
		t.Fatal("the generation did not finish")
	}
	select {
	case prom = <-promoted:
	case <-deadline:
		t.Fatal("the promote did not finish")
	}
	if !gen.Success || !prom.Success {
		t.Fatalf("generate: %q, promote: %q", gen.Error, prom.Error)
	}
	data := gen.Data.(proto.MLSKeyPackageGenerateResponseData)
	if barrier.activeAtResume != data.LeafSignatureKeyFingerprint {
		t.Fatalf("the pool was written for leaf %s while leaf %s was active",
			data.LeafSignatureKeyFingerprint, barrier.activeAtResume)
	}
	assertKeyPackagesAreFor(t, data, first, second)
	if activeLeafFingerprint(f.deps.Store) != second.SignatureKeyFingerprint {
		t.Fatal("the promote did not take effect after the generation")
	}
}
