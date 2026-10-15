package localrpc

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The App's audit-only path: a grant opens only under its context, and the
// generate route carries the context too.
func TestAppAuditOnlyGrantRoutes(t *testing.T) {
	server, _, own, session, csrf := newKeyedRouteServer(t)
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
	if decodeData[proto.GroupSessionOpenResponseData](t, opened).GroupHandle == "" {
		t.Fatal("open returned no handle")
	}

	code, generated, body := callRoute(t, server, session, csrf, "/v1/group-dek/generate", map[string]any{"grant_context": gc})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	if decodeData[proto.GroupDEKGenerateAndOpenResponseData](t, generated).GroupHandle == "" {
		t.Fatal("generate returned no handle")
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
