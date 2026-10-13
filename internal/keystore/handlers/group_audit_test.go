// group_audit_test.go — audit-only Group DEK versions: grant labels, handle
// policy, the three audit actions and their single-use authorizations.
//
// testdata/audit-dek-policy-v1.json is the cross-repository golden vector:
// ariadne and dragpass check in the same file. This test reproduces the label,
// the AAD, the token key, the sealed fixture token and both canonicals.

package handlers

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type auditVectors struct {
	OrgID                    string  `json:"org_id"`
	GroupID                  string  `json:"group_id"`
	DekVersion               int     `json:"dek_version"`
	TableID                  string  `json:"table_id"`
	AccountID                string  `json:"account_id"`
	PermitID                 string  `json:"permit_id"`
	GrantLabelAuditOnlyV1    string  `json:"grant_label_audit_only_v1"`
	GrantLabelLegacy         *string `json:"grant_label_legacy"`
	AuditAAD                 string  `json:"audit_aad"`
	GroupDEKHex              string  `json:"group_dek_hex"`
	TableHex                 string  `json:"table_hex"`
	TableSHA256              string  `json:"table_sha256"`
	TokenKeyHex              string  `json:"token_key_hex"`
	IVHex                    string  `json:"iv_hex"`
	Plaintext                string  `json:"plaintext"`
	CiphertextHex            string  `json:"ciphertext_hex"`
	NegativeRawDEKCiphertext string  `json:"negative_raw_dek_ciphertext_hex"`
	TableReceipt             struct {
		proto.AuditTableReceipt
		Canonical string `json:"canonical"`
	} `json:"table_receipt"`
	DecryptPermit struct {
		proto.AuditDecryptPermit
		Canonical string `json:"canonical"`
	} `json:"decrypt_permit"`
}

func loadAuditVectors(t *testing.T) auditVectors {
	t.Helper()
	raw, err := os.ReadFile("../testdata/audit-dek-policy-v1.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v auditVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestAuditGoldenVectors(t *testing.T) {
	v := loadAuditVectors(t)
	gc := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: v.DekVersion}
	if got := string(proto.GroupDEKGrantLabel(gc)); got != v.GrantLabelAuditOnlyV1 {
		t.Fatalf("label = %q", got)
	}
	legacy := &proto.GrantContext{Policy: proto.GrantPolicyLegacy, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: v.DekVersion}
	if proto.GroupDEKGrantLabel(legacy) != nil || proto.GroupDEKGrantLabel(nil) != nil || v.GrantLabelLegacy != nil {
		t.Fatal("legacy label must be nil")
	}
	if got := proto.AuditDragAADCanonical(v.OrgID, v.GroupID, v.DekVersion, v.TableID); got != v.AuditAAD {
		t.Fatalf("aad = %q", got)
	}
	table := mustHex(t, v.TableHex)
	sum := sha256.Sum256(table)
	if hex.EncodeToString(sum[:]) != v.TableSHA256 {
		t.Fatal("table sha256 mismatch")
	}
	key, err := deriveAuditTokenKey(mustHex(t, v.GroupDEKHex), table, v.AuditAAD)
	if err != nil || hex.EncodeToString(key) != v.TokenKeyHex {
		t.Fatalf("token key = %x err=%v", key, err)
	}
	pt, err := crypto.OpenAESGCM(key, mustHex(t, v.IVHex), mustHex(t, v.CiphertextHex), []byte(v.AuditAAD))
	if err != nil || string(pt) != v.Plaintext {
		t.Fatalf("fixture token did not open: %v", err)
	}
	// The same plaintext sealed with the raw Group DEK and the same AAD (what a
	// caller-chosen AAD path would produce) does not open under the token key.
	if _, err := crypto.OpenAESGCM(key, mustHex(t, v.IVHex), mustHex(t, v.NegativeRawDEKCiphertext), []byte(v.AuditAAD)); err == nil {
		t.Fatal("a raw-DEK seal opened under the token key")
	}
	if got := proto.AuditTableReceiptCanonical(v.TableReceipt.AuditTableReceipt); got != v.TableReceipt.Canonical {
		t.Fatalf("receipt canonical = %q", got)
	}
	if got := proto.AuditDecryptPermitCanonical(v.DecryptPermit.AuditDecryptPermit); got != v.DecryptPermit.Canonical {
		t.Fatalf("permit canonical = %q", got)
	}
}

// ─── Harness ─────────────────────────────────────────────────────────────

type auditFixture struct {
	deps   Deps
	clock  *msgTestClock
	key    *rsa.PrivateKey
	v      auditVectors
	table  []byte
	handle string
	gc     *proto.GrantContext
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	deps, _, store := newTestDeps(t)
	deps.AuditAuthorizations = NewAuditAuthorizationStore()
	deps.Clipboard = clipboard.NewMemoryClipboard()
	clock := &msgTestClock{unix: 1788999000}
	deps.Clock = clock.now
	key := msgTestServerKey()
	deps.ServerKeyVerifier = msgTestVerifier{version: 1, public: &key.PublicKey}
	v := loadAuditVectors(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	f := &auditFixture{deps: deps, clock: clock, key: key, v: v, table: mustHex(t, v.TableHex)}
	f.gc = &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: v.DekVersion}
	f.handle = f.openWith(t, f.wrapToMe(t, pubPEM, f.gc), f.gc)
	return f
}

func (f *auditFixture) wrapToMe(t *testing.T, pubPEM string, gc *proto.GrantContext) string {
	t.Helper()
	pub, err := crypto.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapGrant(pub, mustHex(t, f.v.GroupDEKHex), gc)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

func (f *auditFixture) openWith(t *testing.T, grant string, gc *proto.GrantContext) string {
	t.Helper()
	resp := HandleGroupSessionOpen(f.deps, proto.GroupSessionOpenRequest{EncryptedGroupDEK: grant, GrantContext: gc})
	if !resp.Success {
		t.Fatalf("open: %s %s", resp.ErrorCode, resp.Error)
	}
	handle := resp.Data.(proto.GroupSessionOpenResponseData).GroupHandle
	t.Cleanup(func() { f.deps.GroupSessions.Close(handle) })
	return handle
}

func (f *auditFixture) sign(t *testing.T, canonical string) string {
	t.Helper()
	sig, err := crypto.SignData(f.key, canonical)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (f *auditFixture) receipt(t *testing.T, mutate func(*proto.AuditTableReceipt)) proto.AuditTableReceipt {
	t.Helper()
	r := f.v.TableReceipt.AuditTableReceipt
	if mutate != nil {
		mutate(&r)
	}
	r.Signature = f.sign(t, proto.AuditTableReceiptCanonical(r))
	return r
}

func (f *auditFixture) permit(t *testing.T, mutate func(*proto.AuditDecryptPermit)) proto.AuditDecryptPermit {
	t.Helper()
	p := f.v.DecryptPermit.AuditDecryptPermit
	if mutate != nil {
		mutate(&p)
	}
	p.Signature = f.sign(t, proto.AuditDecryptPermitCanonical(p))
	return p
}

func (f *auditFixture) encryptRequest(receipt proto.AuditTableReceipt) proto.GroupEncryptAuditRequest {
	return proto.GroupEncryptAuditRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table),
		Receipt: receipt, PlaintextB64: base64.StdEncoding.EncodeToString([]byte(f.v.Plaintext)),
	}
}

func (f *auditFixture) decryptRequest(t *testing.T, permit proto.AuditDecryptPermit, iv, ct []byte) proto.GroupDecryptAuditToClipboardRequest {
	return proto.GroupDecryptAuditToClipboardRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table),
		Permit: permit, IVB64: base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ct), ClipboardTTLMs: 10_000,
	}
}

func payloadOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wantCode(t *testing.T, resp proto.BaseResponse, code string) {
	t.Helper()
	if resp.Success || resp.ErrorCode != code {
		t.Fatalf("want %s, got success=%t code=%q err=%q", code, resp.Success, resp.ErrorCode, resp.Error)
	}
}

// ─── Grant labels ────────────────────────────────────────────────────────

func TestAuditGrantLabelCannotBeDowngradedOrMoved(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	pub, _ := crypto.ParsePublicKey(pubPEM)
	audit := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: 3}
	auditGrant, _ := wrapGrant(pub, mustHex(t, v.GroupDEKHex), audit)
	legacyGrant, _ := wrapGrant(pub, mustHex(t, v.GroupDEKHex), nil)
	open := func(grant []byte, gc *proto.GrantContext) proto.BaseResponse {
		return HandleGroupSessionOpen(deps, proto.GroupSessionOpenRequest{
			EncryptedGroupDEK: base64.StdEncoding.EncodeToString(grant), GrantContext: gc,
		})
	}
	// An audit-only grant presented as legacy, with no context, or with any
	// slot changed does not open.
	if resp := open(auditGrant, nil); resp.Success || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("audit grant opened without its label: %+v", resp)
	}
	legacyClaim := *audit
	legacyClaim.Policy = proto.GrantPolicyLegacy
	if resp := open(auditGrant, &legacyClaim); resp.Success {
		t.Fatal("audit grant opened as legacy")
	}
	for name, mutate := range map[string]func(*proto.GrantContext){
		"org":     func(c *proto.GrantContext) { c.OrgID = v.AccountID },
		"group":   func(c *proto.GrantContext) { c.GroupID = v.AccountID },
		"version": func(c *proto.GrantContext) { c.DekVersion = 4 },
	} {
		moved := *audit
		mutate(&moved)
		wantCode(t, open(auditGrant, &moved), proto.GroupGrantPolicyMismatch)
		_ = name
	}
	// A legacy grant claimed as audit-only does not open either.
	wantCode(t, open(legacyGrant, audit), proto.GroupGrantPolicyMismatch)
	// The legacy path is byte-for-byte the old one.
	if resp := open(legacyGrant, nil); !resp.Success {
		t.Fatalf("legacy grant: %+v", resp)
	}
	if resp := open(auditGrant, audit); !resp.Success {
		t.Fatalf("audit grant under its label: %+v", resp)
	}
}

func TestAuditGrantRewrapsKeepTheLabel(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	dek := mustHex(t, v.GroupDEKHex)
	pub, _ := crypto.ParsePublicKey(pubPEM)
	audit := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: 3}
	mine, _ := wrapGrant(pub, dek, audit)
	mineB64 := base64.StdEncoding.EncodeToString(mine)
	peer, _ := crypto.GenerateRSAKeyPair()
	peerPriv, _ := crypto.ParsePrivateKey(peer.PrivateKey)
	label := proto.GroupDEKGrantLabel(audit)

	checkLabeled := func(name, wrappedB64 string) {
		t.Helper()
		wrapped, _ := base64.StdEncoding.DecodeString(wrappedB64)
		if _, err := crypto.DecryptData(peerPriv, wrapped); err == nil {
			t.Fatalf("%s: output opened without the label", name)
		}
		got, err := crypto.DecryptDataWithLabel(peerPriv, wrapped, label)
		if err != nil || hex.EncodeToString(got) != v.GroupDEKHex {
			t.Fatalf("%s: output did not open under the label: %v", name, err)
		}
	}

	member := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: mineB64, OtherPublicKey: peer.PublicKey, GrantContext: audit,
	})
	if !member.Success {
		t.Fatalf("rewrap for member: %+v", member)
	}
	checkLabeled("dek_rewrap_for_member", member.Data.(proto.DEKRewrapForMemberResponseData).EncryptedForOtherB64)

	many := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: mineB64, Recipients: exemptRecipients(peer.PublicKey), GrantContext: audit,
	})
	if !many.Success {
		t.Fatalf("rewrap for many: %+v", many)
	}
	checkLabeled("dek_unwrap_and_rewrap_for_many", many.Data.(proto.DEKUnwrapAndRewrapForManyResponseData).EncryptedForRecipientsB64[0])

	// Without the context the audit grant does not even open for a rewrap.
	refused := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: mineB64, OtherPublicKey: peer.PublicKey,
	})
	if refused.Success {
		t.Fatal("audit grant rewrapped without its context")
	}
}

func TestAuditGenerateAndOpenSelfChecksItsOwnWrap(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, privPEM := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	audit := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: 4}
	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{MyPublicKey: pubPEM, GrantContext: audit})
	if !resp.Success {
		t.Fatalf("generate: %+v", resp)
	}
	data := resp.Data.(proto.GroupDEKGenerateAndOpenResponseData)
	priv, _ := crypto.ParsePrivateKey(privPEM)
	wrapped, _ := base64.StdEncoding.DecodeString(data.EncryptedForMeB64)
	if _, err := crypto.DecryptData(priv, wrapped); err == nil {
		t.Fatal("generated audit grant opened without the label")
	}
	label, err := deps.GroupSessions.LabelOf(data.GroupHandle)
	if err != nil || !isAuditOnlyLabel(label) || label.DekVersion != 4 {
		t.Fatalf("generated handle label = %+v err=%v", label, err)
	}
	// An audit-only grant wrapped to somebody else's key is refused: the self
	// check cannot open it.
	other, _ := crypto.GenerateRSAKeyPair()
	refused := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{MyPublicKey: other.PublicKey, GrantContext: audit})
	if refused.Success || refused.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("generate to a foreign key: %+v", refused)
	}
}

// ─── Handle policy ───────────────────────────────────────────────────────

func TestAuditOnlyHandleRefusesTheAADFreeDragActions(t *testing.T) {
	f := newAuditFixture(t)
	iv := base64.StdEncoding.EncodeToString(make([]byte, 12))
	ct := base64.StdEncoding.EncodeToString(make([]byte, 32))
	wantCode(t, HandleGroupEncrypt(f.deps, proto.GroupEncryptRequest{GroupHandle: f.handle, PlaintextB64: "aGk="}), proto.GroupPolicyAuditOnly)
	wantCode(t, HandleGroupDecryptToClipboard(f.deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle: f.handle, IVB64: iv, CiphertextB64: ct, ClipboardTTLMs: 10_000,
	}), proto.GroupPolicyAuditOnly)
	wantCode(t, HandleGroupTranscryptForGuest(f.deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle: f.handle, IVB64: iv, CiphertextB64: ct,
	}), proto.GroupPolicyAuditOnly)

	// The credential seal and the message seal still work on it.
	if resp := HandleGroupEncryptWithAAD(f.deps, proto.GroupEncryptWithAADRequest{
		GroupHandle: f.handle, PlaintextB64: "aGk=",
		AADB64: base64.StdEncoding.EncodeToString([]byte(f.v.OrgID + "|entry|kind|1|3")),
	}); !resp.Success {
		t.Fatalf("credential seal on an audit-only handle: %+v", resp)
	}
	if resp := HandleMessageSeal(f.deps, proto.MessageSealRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: 3,
		TokenExpiresAt: 2000000000, PlaintextB64: "aGk=",
	}); !resp.Success {
		t.Fatalf("message seal on an audit-only handle: %+v", resp)
	}
}

func TestAuditActionsRefuseALegacyOrForeignHandle(t *testing.T) {
	f := newAuditFixture(t)
	legacyHandle, _ := openSessionForFreshKey(t, f.deps)
	req := f.encryptRequest(f.receipt(t, nil))
	req.GroupHandle = legacyHandle
	wantCode(t, HandleGroupEncryptAudit(f.deps, payloadOf(t, req)), proto.GroupPolicyNotAuditOnly)

	// Same handle, but the request names another version: refused before the
	// receipt is spent, so the receipt still works afterwards.
	req = f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.DekVersion = 4 }))
	req.DekVersion = 4
	wantCode(t, HandleGroupEncryptAudit(f.deps, payloadOf(t, req)), proto.GroupPolicyNotAuditOnly)
	if resp := HandleGroupEncryptAudit(f.deps, payloadOf(t, f.encryptRequest(f.receipt(t, nil)))); !resp.Success {
		t.Fatalf("receipt was spent by a refused request: %+v", resp)
	}
}

// ─── Audit actions ───────────────────────────────────────────────────────

func TestAuditEncryptDecryptTranscryptRoundTrip(t *testing.T) {
	f := newAuditFixture(t)
	enc := HandleGroupEncryptAudit(f.deps, payloadOf(t, f.encryptRequest(f.receipt(t, nil))))
	if !enc.Success {
		t.Fatalf("encrypt: %+v", enc)
	}
	sealed := enc.Data.(proto.GroupEncryptResponseData)
	iv, _ := base64.StdEncoding.DecodeString(sealed.IVB64)
	ct, _ := base64.StdEncoding.DecodeString(sealed.CiphertextB64)

	// The token is not a raw-DEK seal: neither the raw DEK nor the raw DEK with
	// the audit AAD opens it.
	if _, err := crypto.OpenAESGCM(mustHex(t, f.v.GroupDEKHex), iv, ct, nil); err == nil {
		t.Fatal("audit token opened under the raw DEK")
	}
	if _, err := crypto.OpenAESGCM(mustHex(t, f.v.GroupDEKHex), iv, ct, []byte(f.v.AuditAAD)); err == nil {
		t.Fatal("audit token opened under the raw DEK with the AAD")
	}

	dec := HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, f.decryptRequest(t, f.permit(t, nil), iv, ct)))
	if !dec.Success {
		t.Fatalf("decrypt: %+v", dec)
	}
	if strings.Contains(string(payloadOf(t, dec)), f.v.Plaintext) {
		t.Fatal("plaintext in the clipboard response")
	}

	tr := proto.GroupTranscryptAuditForGuestRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: 3,
		TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table),
		Permit: f.permit(t, func(p *proto.AuditDecryptPermit) { p.PermitID = f.v.AccountID }),
		IVB64:  sealed.IVB64, CiphertextB64: sealed.CiphertextB64,
	}
	guest := HandleGroupTranscryptAuditForGuest(f.deps, payloadOf(t, tr))
	if !guest.Success {
		t.Fatalf("transcrypt: %+v", guest)
	}
	g := guest.Data.(proto.GroupTranscryptForGuestResponseData)
	key, _ := base64.RawURLEncoding.DecodeString(g.GuestKey)
	payload, _ := base64.StdEncoding.DecodeString(g.GuestCiphertext)
	pt, err := crypto.OpenAESGCM(key, payload[:12], payload[12:], nil)
	if err != nil || string(pt) != f.v.Plaintext {
		t.Fatalf("guest share did not open: %v", err)
	}
}

func TestAuditTokenKeyDependsOnTheTable(t *testing.T) {
	f := newAuditFixture(t)
	key := mustHex(t, f.v.TokenKeyHex)
	iv, ct := mustHex(t, f.v.IVHex), mustHex(t, f.v.CiphertextHex)
	if _, err := crypto.OpenAESGCM(key, iv, ct, []byte(f.v.AuditAAD)); err != nil {
		t.Fatal(err)
	}
	// Decrypt the golden token with a permit and the table it was made with.
	if resp := HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, f.decryptRequest(t, f.permit(t, nil), iv, ct))); !resp.Success {
		t.Fatalf("golden token: %+v", resp)
	}
	// Another table (signed for, so only the derivation differs) fails the tag.
	other := append([]byte(nil), f.table...)
	other[0], other[1] = other[1], other[0]
	sum := sha256.Sum256(other)
	req := f.decryptRequest(t, f.permit(t, func(p *proto.AuditDecryptPermit) {
		p.PermitID = f.v.AccountID
		p.TableSHA256 = hex.EncodeToString(sum[:])
	}), iv, ct)
	req.TableB64 = base64.StdEncoding.EncodeToString(other)
	wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, req)), proto.AuditDecryptFailed)

	// Another table id (also signed for) changes the AAD and fails the tag.
	req = f.decryptRequest(t, f.permit(t, func(p *proto.AuditDecryptPermit) {
		p.PermitID = f.v.OrgID
		p.TableID = f.v.GroupID
	}), iv, ct)
	req.TableID = f.v.GroupID
	wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, req)), proto.AuditDecryptFailed)
}

func TestAuditAuthorizationRefusals(t *testing.T) {
	f := newAuditFixture(t)
	iv, ct := mustHex(t, f.v.IVHex), mustHex(t, f.v.CiphertextHex)
	cases := map[string]func() json.RawMessage{
		"forged receipt signature": func() json.RawMessage {
			r := f.receipt(t, nil)
			r.Signature = f.sign(t, "something else")
			return payloadOf(t, f.encryptRequest(r))
		},
		"receipt for another table bytes": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.TableSHA256 = strings.Repeat("0", 64) })))
		},
		"receipt for another org": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.OrgID = f.v.AccountID })))
		},
		"receipt for another group": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.GroupID = f.v.AccountID })))
		},
		"receipt for another table": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.TableID = f.v.AccountID })))
		},
		"expired receipt": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.IssuedAt -= 60; r.ExpiresAt -= 60 })))
		},
		"receipt from the future": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.IssuedAt += 30; r.ExpiresAt += 30 })))
		},
		"receipt with a wider window": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.ExpiresAt += 60 })))
		},
		"receipt under an unknown key version": func() json.RawMessage {
			return payloadOf(t, f.encryptRequest(f.receipt(t, func(r *proto.AuditTableReceipt) { r.ServerKeyVersion = 2 })))
		},
		"decrypt permit used as a receipt": func() json.RawMessage {
			p := f.permit(t, nil)
			r := f.receipt(t, nil)
			r.Signature = p.Signature
			return payloadOf(t, f.encryptRequest(r))
		},
		"expired permit": func() json.RawMessage {
			return payloadOf(t, f.decryptRequest(t, f.permit(t, func(p *proto.AuditDecryptPermit) { p.IssuedAt -= 30; p.ExpiresAt -= 30 }), iv, ct))
		},
		"permit for another version": func() json.RawMessage {
			return payloadOf(t, f.decryptRequest(t, f.permit(t, func(p *proto.AuditDecryptPermit) { p.DekVersion = 9 }), iv, ct))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			var resp proto.BaseResponse
			payload := build()
			if strings.Contains(name, "permit") && !strings.Contains(name, "receipt") {
				resp = HandleGroupDecryptAuditToClipboard(f.deps, payload)
			} else {
				resp = HandleGroupEncryptAudit(f.deps, payload)
			}
			wantCode(t, resp, proto.AuditNotAuthorized)
		})
	}
}

func TestAuditAuthorizationsAreSingleUse(t *testing.T) {
	f := newAuditFixture(t)
	receipt := f.receipt(t, nil)
	if resp := HandleGroupEncryptAudit(f.deps, payloadOf(t, f.encryptRequest(receipt))); !resp.Success {
		t.Fatalf("first use: %+v", resp)
	}
	wantCode(t, HandleGroupEncryptAudit(f.deps, payloadOf(t, f.encryptRequest(receipt))), proto.AuditNotAuthorized)

	// Concurrent replays of one permit leave exactly one winner.
	iv, ct := mustHex(t, f.v.IVHex), mustHex(t, f.v.CiphertextHex)
	payload := payloadOf(t, f.decryptRequest(t, f.permit(t, nil), iv, ct))
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if HandleGroupDecryptAuditToClipboard(f.deps, payload).Success {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("permit replays won %d times", wins)
	}
}

func TestAuditRequestsDecodeStrictly(t *testing.T) {
	f := newAuditFixture(t)
	base := string(payloadOf(t, f.encryptRequest(f.receipt(t, nil))))
	for name, payload := range map[string]string{
		"unknown field":   strings.Replace(base, `{"group_handle"`, `{"aad_b64":"eA==","group_handle"`, 1),
		"duplicate key":   strings.Replace(base, `"dek_version":3,`, `"dek_version":3,"dek_version":4,`, 1),
		"missing receipt": strings.Replace(base, `"receipt":`, `"receipt_x":`, 1),
		"short table":     strings.Replace(base, `"table_b64":"`, `"table_b64":"AAAA`, 1),
	} {
		wantCode(t, HandleGroupEncryptAudit(f.deps, json.RawMessage(payload)), proto.AuditInvalidInput)
		_ = name
	}
}

func TestReservedAADDomainsAreRefusedToCallers(t *testing.T) {
	f := newAuditFixture(t)
	legacyHandle, _ := openSessionForFreshKey(t, f.deps)
	for _, aad := range []string{f.v.AuditAAD, "dragpass.message|1|x", "dragpass.drag.anything"} {
		resp := HandleGroupEncryptWithAAD(f.deps, proto.GroupEncryptWithAADRequest{
			GroupHandle: legacyHandle, PlaintextB64: "aGk=",
			AADB64: base64.StdEncoding.EncodeToString([]byte(aad)),
		})
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("reserved AAD %q accepted: %+v", aad, resp)
		}
	}
	// A credential canonical (UUID first) is not reserved.
	if resp := HandleGroupEncryptWithAAD(f.deps, proto.GroupEncryptWithAADRequest{
		GroupHandle: legacyHandle, PlaintextB64: "aGk=",
		AADB64: base64.StdEncoding.EncodeToString([]byte(f.v.OrgID + "|" + f.v.TableID + "|credential|1|3")),
	}); !resp.Success {
		t.Fatalf("credential canonical refused: %+v", resp)
	}
}

func TestAuditGrantKeepsTheLabelThroughRecoveryAndArchiveRegrants(t *testing.T) {
	v := loadAuditVectors(t)
	dek := mustHex(t, v.GroupDEKHex)
	audit := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: 3}
	label := proto.GroupDEKGrantLabel(audit)

	t.Run("dek_rewrap_with_old_key_to_self", func(t *testing.T) {
		stage := newRecoveryStage(t, false)
		prepared := stage.prepare(t)
		wrapped, _ := wrapGrant(&stage.oldKey.priv.PublicKey, dek, audit)
		if response := saveSessionCode(stage.deps, serverSessionCode(t, prepared.NewPublicKey, stageNewSession)); !response.Success {
			t.Fatalf("save_session_code: %s", response.Error)
		}
		request := proto.DEKRewrapWithOldKeyToSelfRequest{
			ChallengeToken: "server-challenge", Signature: "server-signature",
			RecoveryHandle: prepared.RecoveryHandle, ServerKeyVersion: 1,
			EncryptedGroupDEK: base64.StdEncoding.EncodeToString(wrapped),
		}
		if response := HandleDEKRewrapWithOldKeyToSelf(stage.deps, request); response.Success {
			t.Fatal("audit grant rewrapped without its context")
		}
		request.GrantContext = audit
		response := HandleDEKRewrapWithOldKeyToSelf(stage.deps, request)
		if !response.Success {
			t.Fatalf("rewrap to self: %+v", response)
		}
		out, _ := base64.StdEncoding.DecodeString(response.Data.(proto.DEKRewrapWithOldKeyResponseData).NewEncryptedGroupDEK)
		activePrivate, _ := keychain.GetPrivateKey(stage.store)
		priv, _ := crypto.ParsePrivateKey(activePrivate)
		if _, err := crypto.DecryptData(priv, out); err == nil {
			t.Fatal("recovered grant lost its label")
		}
		if got, err := crypto.DecryptDataWithLabel(priv, out, label); err != nil || hex.EncodeToString(got) != v.GroupDEKHex {
			t.Fatalf("recovered grant under its label: %v", err)
		}
	})

	t.Run("archive_unwrap_and_rewrap", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		archiveKP, _ := crypto.GenerateRSAKeyPair()
		if err := keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey); err != nil {
			t.Fatal(err)
		}
		archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
		wrapped, _ := wrapGrant(archivePub, dek, audit)
		member, _ := crypto.GenerateRSAKeyPair()
		req := proto.ArchiveUnwrapAndRewrapRequest{
			WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrapped),
			RecipientPublicKey:   member.PublicKey,
		}
		if resp := HandleArchiveUnwrapAndRewrap(deps, req); resp.Success {
			t.Fatal("audit archive grant re-granted without its context")
		}
		req.GrantContext = audit
		resp := HandleArchiveUnwrapAndRewrap(deps, req)
		if !resp.Success {
			t.Fatalf("archive re-grant: %+v", resp)
		}
		out, _ := base64.StdEncoding.DecodeString(resp.Data.(proto.ArchiveUnwrapAndRewrapResponseData).EncryptedForOtherB64)
		priv, _ := crypto.ParsePrivateKey(member.PrivateKey)
		if _, err := crypto.DecryptData(priv, out); err == nil {
			t.Fatal("archive re-grant lost its label")
		}
		if _, err := crypto.DecryptDataWithLabel(priv, out, label); err != nil {
			t.Fatalf("archive re-grant under its label: %v", err)
		}
	})
}

func TestAuditGrantKeepsTheLabelThroughAQuorumRegrant(t *testing.T) {
	v := loadAuditVectors(t)
	audit := &proto.GrantContext{Policy: proto.GrantPolicyAuditOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: 3}
	deps, _, store := newTestDeps(t)
	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)
	adminKPs, adminPems := genAdminKeys(t, 3)
	split := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{ThresholdN: 2, RecipientPublicKeys: adminPems})
	if !split.Success {
		t.Fatalf("split: %s", split.Error)
	}
	shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
	sess := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{})
	sessionPub := sess.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey
	rewrapped := []proto.RewrappedShareInput{
		adminRewrapShare(t, adminKPs[0], shares[0], sessionPub),
		adminRewrapShare(t, adminKPs[1], shares[1], sessionPub),
	}
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrapped, _ := wrapGrant(archivePub, mustHex(t, v.GroupDEKHex), audit)
	member, _ := crypto.GenerateRSAKeyPair()
	resp := HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares: rewrapped, WrappedOldDEKB64: base64.StdEncoding.EncodeToString(wrapped),
		Recipients: exemptRecipients(member.PublicKey), GrantContext: audit,
	})
	if !resp.Success {
		t.Fatalf("combine: %+v", resp)
	}
	out, _ := base64.StdEncoding.DecodeString(resp.Data.(proto.ArchiveQuorumCombineAndRewrapResponseData).Grants[0].EncryptedGroupDEKB64)
	priv, _ := crypto.ParsePrivateKey(member.PrivateKey)
	if _, err := crypto.DecryptData(priv, out); err == nil {
		t.Fatal("quorum re-grant lost its label")
	}
	if _, err := crypto.DecryptDataWithLabel(priv, out, proto.GroupDEKGrantLabel(audit)); err != nil {
		t.Fatalf("quorum re-grant under its label: %v", err)
	}
}
