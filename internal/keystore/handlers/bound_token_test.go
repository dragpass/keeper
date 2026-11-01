// Tests for the bound drag-token actions and the refusal of the AAD-free
// drag actions (docs/protocol.md "Bound drag tokens").

package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

const (
	boundOrg     = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	boundGroup   = "1b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e"
	boundOther   = "3d4e5f6a-7b8c-4d9e-8f0a-2b3c4d5e6f70"
	boundTable   = "2c3d4e5f-6a7b-4c8d-ae9f-1a2b3c4d5e6f"
	boundAccount = "6f1c2a8e-3b4d-4c5e-9f60-718293a4b5c6"
	boundNow     = int64(1_800_000_000)
	boundLater   = "1800000100"
	boundSecret  = "BOUND_TOKEN_PLAINTEXT_SENTINEL"
)

type boundGroupFixture struct {
	deps   Deps
	mc     *clipboard.MemoryClipboard
	clock  *msgTestClock
	handle string
	raw    []byte
}

func newBoundGroupFixture(t *testing.T) *boundGroupFixture {
	t.Helper()
	deps, mc := withMemoryClipboard(t)
	clock := &msgTestClock{unix: boundNow}
	deps.Clock = clock.now
	handle, raw := openSessionForFreshKey(t, deps)
	return &boundGroupFixture{deps: deps, mc: mc, clock: clock, handle: handle, raw: raw}
}

func (f *boundGroupFixture) encrypt(t *testing.T, table, expiry string) (iv, ct string) {
	t.Helper()
	resp := HandleGroupEncryptBound(f.deps, proto.GroupEncryptBoundRequest{
		GroupHandle: f.handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7,
		AuditTableID: table, TokenExpiry: expiry,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(boundSecret)),
	})
	if !resp.Success {
		t.Fatalf("bound encrypt: %s %s", resp.ErrorCode, resp.Error)
	}
	data := resp.Data.(proto.GroupEncryptResponseData)
	return data.IVB64, data.CiphertextB64
}

func (f *boundGroupFixture) decryptReq(iv, ct, table, expiry string) proto.GroupDecryptBoundToClipboardRequest {
	return proto.GroupDecryptBoundToClipboardRequest{
		GroupHandle: f.handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7,
		AuditTableID: table, TokenExpiry: expiry,
		IVB64: iv, CiphertextB64: ct, ClipboardTTLMs: 30_000,
	}
}

func TestBoundGroupTokenRoundTripsWithExpiryAndNever(t *testing.T) {
	for _, tc := range []struct{ table, expiry string }{
		{"", "never"}, {"", boundLater}, {boundTable, "never"}, {boundTable, boundLater},
	} {
		f := newBoundGroupFixture(t)
		iv, ct := f.encrypt(t, tc.table, tc.expiry)

		// The seal is bound: the raw DEK without the canonical AAD does not open it.
		ivRaw, _ := base64.StdEncoding.DecodeString(iv)
		ctRaw, _ := base64.StdEncoding.DecodeString(ct)
		if _, err := crypto.OpenAESGCM(f.raw, ivRaw, ctRaw, nil); err == nil {
			t.Fatalf("%+v: bound token opened without AAD", tc)
		}
		expiry, _ := proto.ParseTokenExpiry(tc.expiry)
		aad := proto.BoundGroupTokenAAD(boundOrg, boundGroup, 7, tc.table, expiry)
		if _, err := crypto.OpenAESGCM(f.raw, ivRaw, ctRaw, []byte(aad)); err != nil {
			t.Fatalf("%+v: not sealed under the canonical AAD: %v", tc, err)
		}

		resp := HandleGroupDecryptBoundToClipboard(f.deps, f.decryptReq(iv, ct, tc.table, tc.expiry))
		if !resp.Success {
			t.Fatalf("%+v: bound decrypt: %s %s", tc, resp.ErrorCode, resp.Error)
		}
		if f.mc.WriteCount() != 1 {
			t.Fatalf("%+v: clipboard writes = %d", tc, f.mc.WriteCount())
		}
		raw, _ := json.Marshal(resp)
		if strings.Contains(string(raw), boundSecret) {
			t.Fatalf("plaintext in response: %s", raw)
		}
	}
}

func TestBoundGroupTokenRefusesTamperedOrTransplantedMetadata(t *testing.T) {
	f := newBoundGroupFixture(t)
	iv, ct := f.encrypt(t, "", boundLater)

	mutations := map[string]func(*proto.GroupDecryptBoundToClipboardRequest){
		"expiry changed":  func(r *proto.GroupDecryptBoundToClipboardRequest) { r.TokenExpiry = "1800000200" },
		"expiry to never": func(r *proto.GroupDecryptBoundToClipboardRequest) { r.TokenExpiry = "never" },
		"group moved":     func(r *proto.GroupDecryptBoundToClipboardRequest) { r.GroupID = boundOther },
		"org moved":       func(r *proto.GroupDecryptBoundToClipboardRequest) { r.OrgID = boundOther },
		"version moved":   func(r *proto.GroupDecryptBoundToClipboardRequest) { r.DekVersion = 8 },
		"table added":     func(r *proto.GroupDecryptBoundToClipboardRequest) { r.AuditTableID = boundTable },
	}
	for name, mutate := range mutations {
		req := f.decryptReq(iv, ct, "", boundLater)
		mutate(&req)
		wantCode(t, HandleGroupDecryptBoundToClipboard(f.deps, req), proto.TokenDecryptFailed)
		if f.mc.WriteCount() != 0 {
			t.Fatalf("%s: clipboard written", name)
		}
	}

	// A legacy body (sealed with no AAD) under bound metadata does not open.
	legacyIV, legacyCT, err := crypto.SealAESGCM(rand.Reader, f.raw, []byte(boundSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []string{"never", boundLater} {
		req := f.decryptReq(base64.StdEncoding.EncodeToString(legacyIV), base64.StdEncoding.EncodeToString(legacyCT), "", expiry)
		wantCode(t, HandleGroupDecryptBoundToClipboard(f.deps, req), proto.TokenDecryptFailed)
	}
	if f.mc.WriteCount() != 0 {
		t.Fatal("clipboard written for a refused token")
	}
}

func TestBoundGroupTokenRefusesAMissingExpiry(t *testing.T) {
	f := newBoundGroupFixture(t)
	iv, ct := f.encrypt(t, "", "never")
	for _, expiry := range []string{"", "0"} {
		resp := HandleGroupDecryptBoundToClipboard(f.deps, f.decryptReq(iv, ct, "", expiry))
		if resp.Success {
			t.Fatalf("expiry %q was read as no expiry", expiry)
		}
	}
	if f.mc.WriteCount() != 0 {
		t.Fatal("clipboard written")
	}
}

func TestBoundGroupTokenRefusedAtUseOnceExpired(t *testing.T) {
	f := newBoundGroupFixture(t)
	iv, ct := f.encrypt(t, "", boundLater)
	f.clock.mu.Lock()
	f.clock.unix = 1_800_000_100 // exactly the expiry
	f.clock.mu.Unlock()
	wantCode(t, HandleGroupDecryptBoundToClipboard(f.deps, f.decryptReq(iv, ct, "", boundLater)), proto.TokenExpired)
	if f.mc.WriteCount() != 0 {
		t.Fatal("clipboard written for an expired token")
	}
	// Sealing an already-expired token is refused as well.
	resp := HandleGroupEncryptBound(f.deps, proto.GroupEncryptBoundRequest{
		GroupHandle: f.handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7,
		TokenExpiry: boundLater, PlaintextB64: "aGk=",
	})
	wantCode(t, resp, proto.TokenExpired)
}

func TestBoundGroupTokenHonoursTheHandleLabel(t *testing.T) {
	f := newBoundGroupFixture(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	labeled, _, err := f.deps.GroupSessions.OpenLabeled(append([]byte(nil), raw...), sessions.Label{
		OrgID: boundOrg, GrantPolicy: proto.GrantPolicyDecryptOnlyV1, GroupID: boundGroup, DekVersion: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.deps.GroupSessions.Close(labeled) })

	// A decrypt-only handle seals nothing.
	resp := HandleGroupEncryptBound(f.deps, proto.GroupEncryptBoundRequest{
		GroupHandle: labeled, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7,
		TokenExpiry: "never", PlaintextB64: "aGk=",
	})
	wantCode(t, resp, proto.GroupPolicyDecryptOnly)

	// It opens a token of its own scope only.
	aad := proto.BoundGroupTokenAAD(boundOrg, boundGroup, 7, "", proto.TokenExpiry{})
	iv, ct, err := crypto.SealAESGCM(rand.Reader, raw, []byte(boundSecret), []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	req := proto.GroupDecryptBoundToClipboardRequest{
		GroupHandle: labeled, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, TokenExpiry: "never",
		IVB64: base64.StdEncoding.EncodeToString(iv), CiphertextB64: base64.StdEncoding.EncodeToString(ct),
		ClipboardTTLMs: 30_000,
	}
	if resp := HandleGroupDecryptBoundToClipboard(f.deps, req); !resp.Success {
		t.Fatalf("decrypt-only handle: %s %s", resp.ErrorCode, resp.Error)
	}
	req.DekVersion = 6
	wantCode(t, HandleGroupDecryptBoundToClipboard(f.deps, req), proto.TokenScopeMismatch)

	// An audit-only handle takes only the audit actions.
	audit, _, err := f.deps.GroupSessions.OpenLabeled(append([]byte(nil), raw...), sessions.Label{
		OrgID: boundOrg, GrantPolicy: proto.GrantPolicyAuditOnlyV1, GroupID: boundGroup, DekVersion: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.deps.GroupSessions.Close(audit) })
	req.GroupHandle, req.DekVersion = audit, 7
	wantCode(t, HandleGroupDecryptBoundToClipboard(f.deps, req), proto.GroupPolicyAuditOnly)
}

func TestBoundTokenGoldenSealedVectorOpensUnderTheCanonicalAAD(t *testing.T) {
	raw, err := os.ReadFile("../testdata/bound-token-aad-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupExpiring string `json:"group_expiring"`
		Sealed        struct {
			KeyHex, IVHex, Plaintext, CiphertextHex string
		} `json:"-"`
		SealedRaw map[string]string `json:"sealed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(v.SealedRaw["key_hex"])
	iv, _ := hex.DecodeString(v.SealedRaw["iv_hex"])
	ct, _ := hex.DecodeString(v.SealedRaw["ciphertext_hex"])
	aad := proto.BoundGroupTokenAAD(boundOrg, boundGroup, 7, "", proto.TokenExpiry{ExpiresAt: 1893456000})
	if aad != v.GroupExpiring {
		t.Fatalf("canonical drift: %q", aad)
	}
	pt, err := crypto.OpenAESGCM(key, iv, ct, []byte(aad))
	if err != nil || string(pt) != v.SealedRaw["plaintext"] {
		t.Fatalf("golden vector did not open: %v", err)
	}
}

// ─── Personal ────────────────────────────────────────────────────────────

func newBoundPersonalFixture(t *testing.T) (Deps, *clipboard.MemoryClipboard, *msgTestClock, string, []byte) {
	t.Helper()
	deps, wrapped, dek := sealPersonalWithAAD(t)
	mc := clipboard.NewMemoryClipboard()
	deps.Clipboard = mc
	clock := &msgTestClock{unix: boundNow}
	deps.Clock = clock.now
	if _, _, err := keychain.SetAccountBinding(deps.Store, boundAccount, "alice", true); err != nil {
		t.Fatal(err)
	}
	return deps, mc, clock, wrapped, dek
}

func TestBoundPersonalTokenRoundTripsAndBindsTheAccount(t *testing.T) {
	for _, expiry := range []string{"never", boundLater} {
		deps, mc, _, wrapped, dek := newBoundPersonalFixture(t)
		enc := HandleDEKUnwrapAndEncryptBound(deps, proto.DEKUnwrapAndEncryptBoundRequest{
			EncryptedDEKB64: wrapped, TokenExpiry: expiry,
			PlaintextB64: base64.StdEncoding.EncodeToString([]byte(boundSecret)),
		})
		if !enc.Success {
			t.Fatalf("personal bound encrypt: %s %s", enc.ErrorCode, enc.Error)
		}
		data := enc.Data.(proto.DEKUnwrapAndEncryptResponseData)
		ivRaw, _ := base64.StdEncoding.DecodeString(data.IVB64)
		ctRaw, _ := base64.StdEncoding.DecodeString(data.CiphertextB64)
		parsed, _ := proto.ParseTokenExpiry(expiry)
		if _, err := crypto.OpenAESGCM(dek, ivRaw, ctRaw, []byte(proto.BoundPersonalTokenAAD(boundAccount, parsed))); err != nil {
			t.Fatalf("not sealed under the personal canonical: %v", err)
		}
		req := proto.DEKUnwrapAndDecryptBoundToClipboardRequest{
			EncryptedDEKB64: wrapped, TokenExpiry: expiry,
			IVB64: data.IVB64, CiphertextB64: data.CiphertextB64, ClipboardTTLMs: 30_000,
		}
		if resp := HandleDEKUnwrapAndDecryptBoundToClipboard(deps, req); !resp.Success {
			t.Fatalf("personal bound decrypt: %s %s", resp.ErrorCode, resp.Error)
		}
		if mc.WriteCount() != 1 {
			t.Fatalf("clipboard writes = %d", mc.WriteCount())
		}

		// Another signed-in account's AAD does not open it.
		if _, _, err := keychain.SetAccountBinding(deps.Store, boundOther, "bob", true); err != nil {
			t.Fatal(err)
		}
		wantCode(t, HandleDEKUnwrapAndDecryptBoundToClipboard(deps, req), proto.TokenDecryptFailed)
	}
}

func TestBoundPersonalTokenRefusals(t *testing.T) {
	deps, mc, clock, wrapped, dek := newBoundPersonalFixture(t)
	enc := HandleDEKUnwrapAndEncryptBound(deps, proto.DEKUnwrapAndEncryptBoundRequest{
		EncryptedDEKB64: wrapped, TokenExpiry: boundLater,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(boundSecret)),
	})
	if !enc.Success {
		t.Fatalf("encrypt: %s", enc.Error)
	}
	data := enc.Data.(proto.DEKUnwrapAndEncryptResponseData)
	req := proto.DEKUnwrapAndDecryptBoundToClipboardRequest{
		EncryptedDEKB64: wrapped, TokenExpiry: boundLater,
		IVB64: data.IVB64, CiphertextB64: data.CiphertextB64, ClipboardTTLMs: 30_000,
	}

	tampered := req
	tampered.TokenExpiry = "never"
	wantCode(t, HandleDEKUnwrapAndDecryptBoundToClipboard(deps, tampered), proto.TokenDecryptFailed)

	legacyIV, legacyCT, err := crypto.SealAESGCM(rand.Reader, dek, []byte(boundSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := req
	legacy.TokenExpiry = "never"
	legacy.IVB64 = base64.StdEncoding.EncodeToString(legacyIV)
	legacy.CiphertextB64 = base64.StdEncoding.EncodeToString(legacyCT)
	wantCode(t, HandleDEKUnwrapAndDecryptBoundToClipboard(deps, legacy), proto.TokenDecryptFailed)

	clock.mu.Lock()
	clock.unix = 1_800_000_100
	clock.mu.Unlock()
	wantCode(t, HandleDEKUnwrapAndDecryptBoundToClipboard(deps, req), proto.TokenExpired)

	if _, _, err := keychain.SignOutAccountBinding(deps.Store); err != nil {
		t.Fatal(err)
	}
	clock.mu.Lock()
	clock.unix = boundNow
	clock.mu.Unlock()
	wantCode(t, HandleDEKUnwrapAndDecryptBoundToClipboard(deps, req), proto.TokenAccountUnbound)
	if mc.WriteCount() != 0 {
		t.Fatal("clipboard written for a refused token")
	}
}

// ─── Legacy refusal ──────────────────────────────────────────────────────

func TestAADFreeDragActionsAreRefusedAsLegacy(t *testing.T) {
	f := newBoundGroupFixture(t)
	iv, ct, err := crypto.SealAESGCM(rand.Reader, f.raw, []byte(boundSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, HandleGroupDecryptToClipboard(f.deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle: f.handle, IVB64: base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ct), ClipboardTTLMs: 30_000,
	}), proto.TokenLegacyRefused)
	wantCode(t, HandleGroupEncrypt(f.deps, proto.GroupEncryptRequest{GroupHandle: f.handle, PlaintextB64: "aGk="}),
		proto.TokenLegacyRefused)

	deps, mc, _, wrapped, dek := newBoundPersonalFixture(t)
	piv, pct, err := crypto.SealAESGCM(rand.Reader, dek, []byte(boundSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, HandleDEKUnwrapAndDecryptToClipboard(deps, proto.DEKUnwrapAndDecryptToClipboardRequest{
		EncryptedDEKB64: wrapped, IVB64: base64.StdEncoding.EncodeToString(piv),
		CiphertextB64: base64.StdEncoding.EncodeToString(pct), ClipboardTTLMs: 30_000,
	}), proto.TokenLegacyRefused)
	wantCode(t, HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		EncryptedDEKB64: wrapped, PlaintextB64: "aGk=",
	}), proto.TokenLegacyRefused)
	if f.mc.WriteCount() != 0 || mc.WriteCount() != 0 {
		t.Fatal("a legacy action wrote the clipboard")
	}
}

// bindBoundTestAccount gives the device the signed-in account a personal bound
// token is sealed for.
func bindBoundTestAccount(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	if _, _, err := keychain.SetAccountBinding(store, boundAccount, "alice", true); err != nil {
		t.Fatal(err)
	}
}

// ─── Audit-only versions ─────────────────────────────────────────────────

// boundAuditToken seals a token the way group_encrypt_audit does under the
// bound AAD, without spending a receipt.
func (f *auditFixture) boundAuditToken(t *testing.T, expiry string) (iv, ct []byte) {
	t.Helper()
	parsed, err := proto.ParseTokenExpiry(expiry)
	if err != nil {
		t.Fatal(err)
	}
	aad := proto.BoundGroupTokenAAD(f.v.OrgID, f.v.GroupID, f.v.DekVersion, f.v.TableID, parsed)
	key, err := deriveAuditTokenKey(mustHex(t, f.v.GroupDEKHex), f.table, aad)
	if err != nil {
		t.Fatal(err)
	}
	iv, ct, err = crypto.SealAESGCM(rand.Reader, key, []byte(f.v.Plaintext), []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	return iv, ct
}

func TestAuditActionsRequireAnAuthenticatedExpiry(t *testing.T) {
	f := newAuditFixture(t)

	// Without token_expiry the request is legacy: refused before the receipt
	// or permit is spent.
	legacyEnc := f.encryptRequest(f.receipt(t, nil))
	legacyEnc.TokenExpiry = ""
	wantCode(t, HandleGroupEncryptAudit(f.deps, payloadOf(t, legacyEnc)), proto.TokenLegacyRefused)
	iv, ct := mustHex(t, f.v.IVHex), mustHex(t, f.v.CiphertextHex)
	legacyDec := f.decryptRequest(t, f.permit(t, nil), iv, ct)
	legacyDec.TokenExpiry = ""
	wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, legacyDec)), proto.TokenLegacyRefused)

	// The golden v1 audit token (AAD without expiry) does not open under any
	// expiry the caller names; the permit above was not spent by the refusal.
	for _, expiry := range []string{"never", "1789999999"} {
		req := f.decryptRequest(t, f.permit(t, nil), iv, ct)
		req.TokenExpiry = expiry
		wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, req)), proto.AuditDecryptFailed)
		f.deps.AuditAuthorizations = NewAuditAuthorizationStore()
	}

	// A bound audit token round-trips through the handler with an expiry, and
	// a changed expiry fails the tag.
	enc := f.encryptRequest(f.receipt(t, nil))
	enc.TokenExpiry = "1789999999"
	sealed := HandleGroupEncryptAudit(f.deps, payloadOf(t, enc))
	if !sealed.Success {
		t.Fatalf("bound audit encrypt: %+v", sealed)
	}
	data := sealed.Data.(proto.GroupEncryptResponseData)
	biv, _ := base64.StdEncoding.DecodeString(data.IVB64)
	bct, _ := base64.StdEncoding.DecodeString(data.CiphertextB64)
	tampered := f.decryptRequest(t, f.permit(t, nil), biv, bct)
	tampered.TokenExpiry = "never"
	wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, tampered)), proto.AuditDecryptFailed)
	f.deps.AuditAuthorizations = NewAuditAuthorizationStore()
	ok := f.decryptRequest(t, f.permit(t, nil), biv, bct)
	ok.TokenExpiry = "1789999999"
	if resp := HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, ok)); !resp.Success {
		t.Fatalf("bound audit decrypt: %+v", resp)
	}

	// Once expired it is refused before the permit is spent.
	f.deps.AuditAuthorizations = NewAuditAuthorizationStore()
	f.clock.mu.Lock()
	f.clock.unix = 1789999999
	f.clock.mu.Unlock()
	expired := f.decryptRequest(t, f.permit(t, func(p *proto.AuditDecryptPermit) {
		p.IssuedAt, p.ExpiresAt = 1789999990, 1789999990+proto.AuditDecryptPermitTTLSeconds
	}), biv, bct)
	expired.TokenExpiry = "1789999999"
	wantCode(t, HandleGroupDecryptAuditToClipboard(f.deps, payloadOf(t, expired)), proto.TokenExpired)
}
