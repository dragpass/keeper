package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

type recoveryProofCase struct {
	deps    Deps
	store   *testdouble.MemorySecretStore
	log     *testdouble.MemoryLogger
	clock   *orgSessionClock
	session proto.ArchiveSessionBeginResponseData
	spki    string
	req     proto.ArchiveRecoverySessionKeyProof
}

// newRecoveryProofCase signs in slotTestAccount on splitTestDevice with the
// App login captured, enrolls a request key and begins testOrgA's session.
func newRecoveryProofCase(t *testing.T) *recoveryProofCase {
	t.Helper()
	d, log, store := newOwnedStageDeps(t)
	clock := &orgSessionClock{now: time.Unix(1789000000, 0)}
	d.Clock = clock.Now
	b, _, err := keychain.GetAccountBinding(store)
	if err != nil {
		t.Fatal(err)
	}
	d.ArchiveRequestLogin = &proto.ArchiveLoginIdentity{AccountID: b.AccountID, Generation: b.ChatStateGeneration}
	if r := HandleRequestKeyGenerate(d, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	session := beginOrgSession(t, d, testOrgA)
	spki, err := crypto.RewrapKeyFingerprint(session.SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &recoveryProofCase{deps: d, store: store, log: log, clock: clock, session: session, spki: spki,
		req: proto.ArchiveRecoverySessionKeyProof{OrgID: testOrgA, GroupID: sessionTestGroup, DekVersion: 3, SessionSPKI: spki}}
}

func (c *recoveryProofCase) sign() proto.BaseResponse {
	return HandleArchiveRecoverySessionKeyProof(c.deps, c.req)
}

func requireRecoveryProofRefused(t *testing.T, r proto.BaseResponse, code errs.ErrorCode) {
	t.Helper()
	if r.Success || r.Data != nil || r.ErrorCode != string(code) {
		t.Fatalf("want refusal %s, got success=%v code=%s data=%v", code, r.Success, r.ErrorCode, r.Data)
	}
}

func requireNoSecretLogged(t *testing.T, log *testdouble.MemoryLogger) {
	t.Helper()
	if log.Contains("PRIVATE KEY") || log.Contains("BEGIN") {
		t.Fatal("key material reached the log")
	}
}

// The signature verifies under the device request key over exactly the
// server's recovery statement for the bound account and device.
func TestArchiveRecoverySessionKeyProofSignsServerStatement(t *testing.T) {
	c := newRecoveryProofCase(t)
	r := c.sign()
	if !r.Success {
		t.Fatal(r.ErrorCode)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Data.(proto.ArchiveSessionKeySignature).Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatal("signature is not standard base64 Ed25519")
	}
	pub64, err := keychain.GetRequestSigningPublicKey(c.store)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(pub64)
	if err != nil {
		t.Fatal(err)
	}
	statement := "dragpass.archive.recovery.session-key|1" +
		"|36:" + slotTestAccount +
		"|36:" + splitTestDevice +
		"|36:" + testOrgA +
		"|36:" + sessionTestGroup +
		"|1:3" +
		"|64:" + c.spki
	if !ed25519.Verify(pub, []byte(statement), sig) {
		t.Fatal("signature does not verify over the server statement")
	}
	requireNoSecretLogged(t, c.log)
	if again := c.sign(); !again.Success {
		t.Fatal("a repeated proof for the same live key was refused:", again.ErrorCode)
	}
}

func TestArchiveRecoverySessionKeyProofRefusesMissingSlot(t *testing.T) {
	c := newRecoveryProofCase(t)
	c.req.OrgID = testOrgB
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeNotFound)
}

func TestArchiveRecoverySessionKeyProofRefusesExpiredSlotAndDeletesIt(t *testing.T) {
	c := newRecoveryProofCase(t)
	c.clock.Set(c.clock.Now().Add(archiveSessionMaxTTL))
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionExpired)
	if orgSlotValue(c.store, testOrgA) != "" || orgSlotPublic(c.store, testOrgA) != "" {
		t.Fatal("expired slot kept")
	}
}

func TestArchiveRecoverySessionKeyProofRefusesUntrustedExpiryAndKeepsSlot(t *testing.T) {
	c := newRecoveryProofCase(t)
	before := c.store.Snapshot()
	c.clock.Set(c.clock.Now().Add(-time.Hour))
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionExpiryUnknown)
	if !reflect.DeepEqual(before, c.store.Snapshot()) {
		t.Fatal("an untrusted slot was changed")
	}
}

// Another organization's slot never answers for the requested one, even
// when the request names that slot's own SPKI.
func TestArchiveRecoverySessionKeyProofIgnoresOtherOrgSlot(t *testing.T) {
	c := newRecoveryProofCase(t)
	other := beginOrgSession(t, c.deps, testOrgB)
	otherSPKI, err := crypto.RewrapKeyFingerprint(other.SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c.req.SessionSPKI = otherSPKI
	before := c.store.Snapshot()
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeNotFound)
	if !reflect.DeepEqual(before, c.store.Snapshot()) {
		t.Fatal("a refused proof changed a slot")
	}
}

// The device-wide slot of earlier Keepers is never read as a session key.
func TestArchiveRecoverySessionKeyProofNeverReadsDeviceWideSlot(t *testing.T) {
	c := newRecoveryProofCase(t)
	legacy, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.Set(config.Service, config.LegacyOrgArchiveSessionPrivateKey, legacy.PrivateKey); err != nil {
		t.Fatal(err)
	}
	legacySPKI, err := crypto.RewrapKeyFingerprint(legacy.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c.req.OrgID = testOrgB
	c.req.SessionSPKI = legacySPKI
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeNotFound)
}

func TestArchiveRecoverySessionKeyProofRefusesFingerprintMismatch(t *testing.T) {
	c := newRecoveryProofCase(t)
	c.req.SessionSPKI = strings.Repeat("0", 64)
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeNotFound)
}

// A slot whose private key does not match its public half is refused, even
// when the request names the private key's own SPKI.
func TestArchiveRecoverySessionKeyProofRequiresMatchingPrivateKey(t *testing.T) {
	c := newRecoveryProofCase(t)
	slot, err := inspectArchiveSessionSlotLocked(c.deps, testOrgA, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	record := encodeArchiveSessionSlot(slot.record, []byte(other.PrivateKey))
	defer record.Destroy()
	if err := keychain.SaveArchiveSessionPrivateKey(c.store, testOrgA, string(record.Bytes())); err != nil {
		t.Fatal(err)
	}
	if c.req.SessionSPKI, err = crypto.RewrapKeyFingerprint(other.PublicKey); err != nil {
		t.Fatal(err)
	}
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeNotFound)
}

func TestArchiveRecoverySessionKeyProofRefusesAnotherLogin(t *testing.T) {
	c := newRecoveryProofCase(t)
	login := *c.deps.ArchiveRequestLogin
	login.Generation = "AAAAAAAAAAAAAAAAAAAAAA"
	c.deps.ArchiveRequestLogin = &login
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionLoginUnavailable)
}

// Another account signed in on this device after the session began: the
// slot belongs to the earlier owner and is not used.
func TestArchiveRecoverySessionKeyProofRefusesOtherAccount(t *testing.T) {
	c := newRecoveryProofCase(t)
	setSlotTestOwner(t, c.deps, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	b, _, err := keychain.GetAccountBinding(c.store)
	if err != nil {
		t.Fatal(err)
	}
	c.deps.ArchiveRequestLogin = &proto.ArchiveLoginIdentity{AccountID: b.AccountID, Generation: b.ChatStateGeneration}
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionOtherOwner)
}

func TestArchiveRecoverySessionKeyProofRefusesSignedOut(t *testing.T) {
	c := newRecoveryProofCase(t)
	if r := HandleAccountBindingSignout(c.deps, proto.AccountBindingSignoutRequest{}); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionLoginUnavailable)
}

func TestArchiveRecoverySessionKeyProofRefusesInvalidRequestBeforeReading(t *testing.T) {
	c := newRecoveryProofCase(t)
	c.req.DekVersion = 0
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeValidation)
}

// signingClockStore moves the clock when the request signing key is read,
// so time passes inside the call between the slot read and the output.
type signingClockStore struct {
	keychain.SecretStore
	onSigningKey func()
}

func (s signingClockStore) Get(service, account string) (string, error) {
	if account == config.DragPassRequestSigningPrivateKey && s.onSigningKey != nil {
		s.onSigningKey()
	}
	return s.SecretStore.Get(service, account)
}

// The slot expires after the signature is made: the re-check before output
// withholds the signature and deletes the expired slot.
func TestArchiveRecoverySessionKeyProofWithholdsSignatureWhenSlotExpiresDuringCall(t *testing.T) {
	c := newRecoveryProofCase(t)
	expiry := c.clock.Now().Add(archiveSessionMaxTTL)
	c.deps.Store = signingClockStore{SecretStore: c.store, onSigningKey: func() { c.clock.Set(expiry) }}
	requireRecoveryProofRefused(t, c.sign(), errs.ErrCodeArchiveSessionExpired)
	if orgSlotValue(c.store, testOrgA) != "" || orgSlotPublic(c.store, testOrgA) != "" {
		t.Fatal("expired slot kept")
	}
}

func TestReservedRecoverySessionSignatureIsSpecificToOneSession(t *testing.T) {
	c := newRecoveryProofCase(t)
	sessionID := "eb7d834a-4a10-4d7c-9686-0083947eb584"
	c.req.SessionID = &sessionID
	r := c.sign()
	if !r.Success {
		t.Fatal(r.ErrorCode)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Data.(proto.ArchiveSessionKeySignature).Signature)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := keychain.GetRequestSigningPublicKey(c.store)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verify := func() bool {
		return ed25519.Verify(pub, []byte(c.req.Canonical(slotTestAccount, splitTestDevice, c.spki)), sig)
	}
	if !verify() {
		t.Fatal("reserved session signature did not verify")
	}
	sessionID = "6b66c02b-509d-4db3-bf45-f2647947e692"
	if verify() {
		t.Fatal("signature accepted for another session")
	}
	c.req.SessionID = nil
	if verify() {
		t.Fatal("signature accepted as a version 1 proof")
	}
}
