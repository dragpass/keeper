package localrpc

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	auditRouteTable  = "44444444-4444-4444-8444-444444444444"
	auditRoutePermit = "55555555-5555-4555-8555-555555555555"
)

// The App's audit-only path: a grant opened under its context, the AAD-free
// external share refused on that handle, and the audit external share served
// under a permit. The generate route carries the context too.
func TestAppAuditOnlyGrantRoutes(t *testing.T) {
	server, store, own, session, csrf := newKeyedRouteServer(t)
	if _, _, err := keychain.SetAccountBinding(store, routePeer, "alice", true); err != nil {
		t.Fatal(err)
	}
	groupDEK := bytes.Repeat([]byte{0x42}, 32)
	gc := map[string]any{"policy": "audit_only_v1", "org_id": routeOwner, "group_id": routeGroup, "dek_version": 5}
	label := proto.GroupDEKGrantLabel(&proto.GrantContext{
		Policy: proto.GrantPolicyAuditOnlyV1, OrgID: routeOwner, GroupID: routeGroup, DekVersion: 5,
	})
	pub, _ := keepercrypto.ParsePublicKey(own)
	wrapped, _ := keepercrypto.EncryptDataWithLabel(pub, groupDEK, label)
	grant := base64.StdEncoding.EncodeToString(wrapped)

	if code, opened, _ := callRoute(t, server, session, csrf, "/v1/group-dek/open",
		map[string]any{"encrypted_group_dek": grant}); code != http.StatusOK || opened.Success {
		t.Fatal("audit-only grant opened without its context")
	}
	code, opened, body := callRoute(t, server, session, csrf, "/v1/group-dek/open",
		map[string]any{"encrypted_group_dek": grant, "grant_context": gc})
	if code != http.StatusOK || !opened.Success {
		t.Fatalf("open: %d %s", code, body)
	}
	handle := decodeData[proto.GroupSessionOpenResponseData](t, opened).GroupHandle

	table := make([]byte, 256)
	for i := range table {
		table[i] = byte(255 - i)
	}
	aad := proto.AuditDragAADCanonical(routeOwner, routeGroup, 5, auditRouteTable)
	salt := sha256.Sum256(table)
	key, _ := hkdf.Key(sha256.New, groupDEK, salt[:], aad, 32)
	iv, ciphertext := gcmSeal(t, key, []byte("audit secret"), []byte(aad))

	if code, refused, _ := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", map[string]any{
		"group_handle": handle, "iv_b64": base64.StdEncoding.EncodeToString(iv),
		"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext), "expected_org_id": routeOwner,
	}); code != http.StatusOK || refused.Success || refused.ErrorCode != proto.GroupPolicyAuditOnly {
		t.Fatalf("AAD-free transcrypt on an audit-only handle: %d %+v", code, refused)
	}

	now := time.Now().Unix()
	permit := map[string]any{
		"permit_id": auditRoutePermit, "table_id": auditRouteTable, "account_id": routePeer,
		"org_id": routeOwner, "group_id": routeGroup, "dek_version": 5,
		"table_sha256": hex.EncodeToString(salt[:]), "issued_at": now, "expires_at": now + 30,
		"server_key_version": 1, "signature": base64.StdEncoding.EncodeToString([]byte("signed")),
	}
	request := map[string]any{
		"group_handle": handle, "org_id": routeOwner, "group_id": routeGroup, "dek_version": 5,
		"table_id": auditRouteTable, "table_b64": base64.StdEncoding.EncodeToString(table),
		"permit": permit, "iv_b64": base64.StdEncoding.EncodeToString(iv),
		"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext),
	}
	code, shared, body := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt-audit", request)
	if code != http.StatusOK || !shared.Success || strings.Contains(body, "audit secret") {
		t.Fatalf("audit transcrypt: %d %s", code, body)
	}
	out := decodeData[proto.GroupTranscryptForGuestResponseData](t, shared)
	guestKey, _ := base64.RawURLEncoding.DecodeString(out.GuestKey)
	payload, _ := base64.StdEncoding.DecodeString(out.GuestCiphertext)
	if string(gcmOpen(t, guestKey, payload[:12], payload[12:], nil)) != "audit secret" {
		t.Fatal("guest share does not carry the token")
	}
	// The permit was consumed.
	if _, replay, _ := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt-audit", request); replay.Success {
		t.Fatal("permit replayed")
	}

	code, generated, body := callRoute(t, server, session, csrf, "/v1/group-dek/generate", map[string]any{"grant_context": gc})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	data := decodeData[proto.GroupDEKGenerateAndOpenResponseData](t, generated)
	if code, refused, _ := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", map[string]any{
		"group_handle": data.GroupHandle, "iv_b64": base64.StdEncoding.EncodeToString(iv),
		"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext), "expected_org_id": routeOwner,
	}); code != http.StatusOK || refused.ErrorCode != proto.GroupPolicyAuditOnly {
		t.Fatalf("generated handle is not audit-only: %d %+v", code, refused)
	}
}

// The App's audit switch narrows a legacy grant to decrypt-only through the
// rewrap-for-many route: the output opens only under the decrypt-only context,
// and a handle from it opens tokens but refuses the message seal.
func TestAppRewrapForManyNarrowsToDecryptOnly(t *testing.T) {
	server, _, own, session, csrf := newKeyedRouteServer(t)
	groupDEK := bytes.Repeat([]byte{0x24}, 32)
	pub, _ := keepercrypto.ParsePublicKey(own)
	legacy, _ := keepercrypto.EncryptDataWithLabel(pub, groupDEK, nil)
	legacyGC := map[string]any{"policy": "legacy", "org_id": routeOwner, "group_id": routeGroup, "dek_version": 2}
	decryptOnlyGC := map[string]any{"policy": "decrypt_only_v1", "org_id": routeOwner, "group_id": routeGroup, "dek_version": 2}

	code, result, body := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-many", map[string]any{
		"wrapped_for_me_b64": base64.StdEncoding.EncodeToString(legacy), "owner_account_id": routeOwner,
		"recipients": []map[string]any{{"public_key": own}}, "grant_context": legacyGC,
		"narrow_to_decrypt_only": true,
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("narrow: %d %s", code, body)
	}
	narrowed := decodeData[proto.DEKUnwrapAndRewrapForManyResponseData](t, result).EncryptedForRecipientsB64[0]

	if code, opened, _ := callRoute(t, server, session, csrf, "/v1/group-dek/open",
		map[string]any{"encrypted_group_dek": narrowed}); code != http.StatusOK || opened.Success {
		t.Fatal("narrowed grant opened without its context")
	}
	code, opened, body := callRoute(t, server, session, csrf, "/v1/group-dek/open",
		map[string]any{"encrypted_group_dek": narrowed, "grant_context": decryptOnlyGC})
	if code != http.StatusOK || !opened.Success {
		t.Fatalf("open narrowed: %d %s", code, body)
	}
	handle := decodeData[proto.GroupSessionOpenResponseData](t, opened).GroupHandle
	if code, sealed, _ := callRoute(t, server, session, csrf, "/v1/message/seal", map[string]any{
		"group_handle": handle, "org_id": routeOwner, "group_id": routeGroup, "dek_version": 2,
		"token_expires_at": 2000000000, "plaintext_b64": "aGk=",
	}); code != http.StatusOK || sealed.Success || sealed.ErrorCode != proto.GroupPolicyDecryptOnly {
		t.Fatalf("message seal on a decrypt-only handle: %d %+v", code, sealed)
	}

	// Narrowing an already-labeled grant is refused.
	if code, refused, _ := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-many", map[string]any{
		"wrapped_for_me_b64": narrowed, "owner_account_id": routeOwner,
		"recipients": []map[string]any{{"public_key": own}}, "grant_context": decryptOnlyGC,
		"narrow_to_decrypt_only": true,
	}); code == http.StatusOK && refused.Success {
		t.Fatal("a decrypt-only grant was narrowed again")
	}
}
