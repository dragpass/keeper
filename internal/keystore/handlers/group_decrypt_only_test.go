// group_decrypt_only_test.go — decrypt-only Group DEK grants: a legacy version
// that an org's audit switch narrowed so it can open existing tokens but seal
// nothing new.

package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func decryptOnlyContext(v auditVectors) *proto.GrantContext {
	return &proto.GrantContext{Policy: proto.GrantPolicyDecryptOnlyV1, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: v.DekVersion}
}

func legacyContext(v auditVectors) *proto.GrantContext {
	return &proto.GrantContext{Policy: proto.GrantPolicyLegacy, OrgID: v.OrgID, GroupID: v.GroupID, DekVersion: v.DekVersion}
}

func TestDecryptOnlyGoldenLabel(t *testing.T) {
	raw, err := os.ReadFile("../testdata/audit-dek-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Label string `json:"grant_label_decrypt_only_v1"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	v := loadAuditVectors(t)
	if got := string(proto.GroupDEKGrantLabel(decryptOnlyContext(v))); got == "" || got != file.Label {
		t.Fatalf("decrypt-only label = %q, want %q", got, file.Label)
	}
}

func TestDecryptOnlyHandleRefusesEverySealAndKeepsDecrypting(t *testing.T) {
	f := newAuditFixture(t)
	gc := decryptOnlyContext(f.v)
	handle := f.openWith(t, f.wrapToMe(t, f.pubPEM, gc), gc)

	wantCode(t, HandleGroupEncrypt(f.deps, proto.GroupEncryptRequest{GroupHandle: handle, PlaintextB64: "aGk="}), proto.GroupPolicyDecryptOnly)
	wantCode(t, HandleGroupEncryptWithAAD(f.deps, proto.GroupEncryptWithAADRequest{
		GroupHandle: handle, PlaintextB64: "aGk=",
		AADB64: base64.StdEncoding.EncodeToString([]byte(f.v.OrgID + "|entry|kind|1|3")),
	}), proto.GroupPolicyDecryptOnly)
	wantCode(t, HandleMessageSeal(f.deps, proto.MessageSealRequest{
		GroupHandle: handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: 3,
		TokenExpiresAt: 2000000000, PlaintextB64: "aGk=",
	}), proto.GroupPolicyDecryptOnly)
	req := f.encryptRequest(f.receipt(t, nil))
	req.GroupHandle = handle
	wantCode(t, HandleGroupEncryptAudit(f.deps, payloadOf(t, req)), proto.GroupPolicyNotAuditOnly)

	// A token sealed before the switch (AAD-free, raw DEK) still opens and can
	// still be shared with a guest.
	iv, ct, err := crypto.SealAESGCM(f.deps.Random(), mustHex(t, f.v.GroupDEKHex), []byte("pre-switch"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp := HandleGroupDecryptToClipboard(f.deps, proto.GroupDecryptToClipboardRequest{
		GroupHandle: handle, IVB64: base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ct), ClipboardTTLMs: 10_000,
	}); !resp.Success {
		t.Fatalf("decrypt on a decrypt-only handle: %+v", resp)
	}
	if resp := HandleGroupTranscryptForGuest(f.deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle: handle, IVB64: base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ct),
	}); !resp.Success {
		t.Fatalf("guest transcrypt on a decrypt-only handle: %+v", resp)
	}
}

func TestDecryptOnlyGrantOpensOnlyUnderItsLabel(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	pub, _ := crypto.ParsePublicKey(pubPEM)
	grant, _ := wrapGrant(pub, mustHex(t, v.GroupDEKHex), decryptOnlyContext(v))
	open := func(gc *proto.GrantContext) proto.BaseResponse {
		return HandleGroupSessionOpen(deps, proto.GroupSessionOpenRequest{
			EncryptedGroupDEK: base64.StdEncoding.EncodeToString(grant), GrantContext: gc,
		})
	}
	if resp := open(nil); resp.Success || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("decrypt-only grant opened with no context: %+v", resp)
	}
	if resp := open(legacyContext(v)); resp.Success {
		t.Fatal("decrypt-only grant opened as legacy")
	}
	audit := decryptOnlyContext(v)
	audit.Policy = proto.GrantPolicyAuditOnlyV1
	wantCode(t, open(audit), proto.GroupGrantPolicyMismatch)
	moved := decryptOnlyContext(v)
	moved.DekVersion = 4
	wantCode(t, open(moved), proto.GroupGrantPolicyMismatch)
	if resp := open(decryptOnlyContext(v)); !resp.Success {
		t.Fatalf("decrypt-only grant under its label: %+v", resp)
	}
}

func TestNarrowToDecryptOnly(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	dek := mustHex(t, v.GroupDEKHex)
	pub, _ := crypto.ParsePublicKey(pubPEM)
	legacyGrant, _ := wrapGrant(pub, dek, nil)
	legacyB64 := base64.StdEncoding.EncodeToString(legacyGrant)
	peer, _ := crypto.GenerateRSAKeyPair()
	peerPriv, _ := crypto.ParsePrivateKey(peer.PrivateKey)

	resp := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: legacyB64, Recipients: exemptRecipients(peer.PublicKey),
		GrantContext: legacyContext(v), NarrowToDecryptOnly: true,
	})
	if !resp.Success {
		t.Fatalf("narrow: %+v", resp)
	}
	out, _ := base64.StdEncoding.DecodeString(resp.Data.(proto.DEKUnwrapAndRewrapForManyResponseData).EncryptedForRecipientsB64[0])
	if _, err := crypto.DecryptData(peerPriv, out); err == nil {
		t.Fatal("narrowed grant opened under the empty label")
	}
	audit := decryptOnlyContext(v)
	audit.Policy = proto.GrantPolicyAuditOnlyV1
	if _, err := crypto.DecryptDataWithLabel(peerPriv, out, proto.GroupDEKGrantLabel(audit)); err == nil {
		t.Fatal("narrowed grant opened under the audit-only label")
	}
	got, err := crypto.DecryptDataWithLabel(peerPriv, out, proto.GroupDEKGrantLabel(decryptOnlyContext(v)))
	if err != nil || hex.EncodeToString(got) != v.GroupDEKHex {
		t.Fatalf("narrowed grant did not open under the decrypt-only label: %v", err)
	}

	// Narrowing never widens and needs the version named.
	auditGrant, _ := wrapGrant(pub, dek, audit)
	doGrant, _ := wrapGrant(pub, dek, decryptOnlyContext(v))
	for name, req := range map[string]proto.DEKUnwrapAndRewrapForManyRequest{
		"no context":   {WrappedForMeB64: legacyB64, NarrowToDecryptOnly: true},
		"audit-only":   {WrappedForMeB64: base64.StdEncoding.EncodeToString(auditGrant), GrantContext: audit, NarrowToDecryptOnly: true},
		"decrypt-only": {WrappedForMeB64: base64.StdEncoding.EncodeToString(doGrant), GrantContext: decryptOnlyContext(v), NarrowToDecryptOnly: true},
	} {
		req.Recipients = exemptRecipients(peer.PublicKey)
		if r := HandleDEKUnwrapAndRewrapForMany(deps, req); r.Success || r.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: narrowing accepted: %+v", name, r)
		}
	}
}

func TestDecryptOnlyGrantRewrapsStayDecryptOnly(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	pub, _ := crypto.ParsePublicKey(pubPEM)
	gc := decryptOnlyContext(v)
	mine, _ := wrapGrant(pub, mustHex(t, v.GroupDEKHex), gc)
	mineB64 := base64.StdEncoding.EncodeToString(mine)
	peer, _ := crypto.GenerateRSAKeyPair()
	peerPriv, _ := crypto.ParsePrivateKey(peer.PrivateKey)
	check := func(name, b64 string) {
		t.Helper()
		w, _ := base64.StdEncoding.DecodeString(b64)
		if _, err := crypto.DecryptData(peerPriv, w); err == nil {
			t.Fatalf("%s: output opened without the label", name)
		}
		if _, err := crypto.DecryptDataWithLabel(peerPriv, w, proto.GroupDEKGrantLabel(gc)); err != nil {
			t.Fatalf("%s: output did not open under the decrypt-only label", name)
		}
	}
	member := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: mineB64, OtherPublicKey: peer.PublicKey, GrantContext: gc,
	})
	if !member.Success {
		t.Fatalf("member: %+v", member)
	}
	check("dek_rewrap_for_member", member.Data.(proto.DEKRewrapForMemberResponseData).EncryptedForOtherB64)
	many := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: mineB64, Recipients: exemptRecipients(peer.PublicKey), GrantContext: gc,
	})
	if !many.Success {
		t.Fatalf("many: %+v", many)
	}
	check("dek_unwrap_and_rewrap_for_many", many.Data.(proto.DEKUnwrapAndRewrapForManyResponseData).EncryptedForRecipientsB64[0])
}

func TestGenerateRefusesADecryptOnlyContext(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)
	v := loadAuditVectors(t)
	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{MyPublicKey: pubPEM, GrantContext: decryptOnlyContext(v)})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("generate under decrypt-only: %+v", resp)
	}
}
