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

// The audit switch cannot change a grant until a server-authorized batch
// decision exists. The direct handler's grant-label behavior is tested in
// handlers; this route must refuse the unsigned request first.
func TestAppRewrapForManyRefusesUnsignedNarrowing(t *testing.T) {
	server, _, own, session, csrf := newKeyedRouteServer(t)
	groupDEK := bytes.Repeat([]byte{0x24}, 32)
	pub, _ := keepercrypto.ParsePublicKey(own)
	legacy, _ := keepercrypto.EncryptDataWithLabel(pub, groupDEK, nil)
	legacyGC := map[string]any{"policy": "legacy", "org_id": routeOwner, "group_id": routeGroup, "dek_version": 2}
	code, result, _ := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-many", map[string]any{
		"wrapped_for_me_b64": base64.StdEncoding.EncodeToString(legacy), "owner_account_id": routeOwner,
		"recipients": []map[string]any{{"public_key": own}}, "grant_context": legacyGC,
		"narrow_to_decrypt_only": true,
	})
	if code != http.StatusOK || result.Success || result.ErrorCode != "not_found" || result.Data != nil {
		t.Fatalf("unsigned audit rewrap accepted: status=%d success=%t code=%s", code, result.Success, result.ErrorCode)
	}
}
