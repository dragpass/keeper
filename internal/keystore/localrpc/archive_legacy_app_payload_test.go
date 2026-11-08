package localrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// An App released before signed archive authority sends these exact shapes.
// A current Keeper must refuse every one of them without returning wrapped
// output, even with the org archive key and a rotation stage present.
func TestPreAuthorityAppArchivePayloadsAreRefused(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	const orgID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	scope := map[string]any{"org_id": orgID}

	code, generated, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_generate", map[string]any{})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	var archive proto.ArchiveKeyGenerateResponseData
	_ = json.Unmarshal(generated.Data, &archive)
	wrapped := wrapTo(t, archive.PublicKey, bytes.Repeat([]byte{0x77}, 32))
	if code, begun, body := callRoute(t, server, session, csrf, "/v1/archive/archive_key_rotate_begin", scope); code != http.StatusOK || !begun.Success {
		t.Fatalf("rotate begin: %d %s", code, body)
	}
	grantContext := map[string]any{"policy": "legacy", "org_id": orgID, "group_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dek_version": 1}
	member, handoff := routeKeypair(t), routeKeypair(t)
	share := map[string]any{
		"wrapped_key": base64.StdEncoding.EncodeToString([]byte("legacy-wrapped")),
		"ciphertext":  base64.StdEncoding.EncodeToString([]byte("legacy-ciphertext")),
	}

	for name, call := range map[string]struct {
		path string
		body map[string]any
	}{
		"rotation rewrap": {"/v1/archive/archive_unwrap_and_rewrap", map[string]any{
			"org_id": orgID, "wrapped_for_archive_b64": wrapped, "to_staged_archive_key": true, "grant_context": grantContext,
		}},
		"ownership handoff": {"/v1/archive/archive_unwrap_and_rewrap", map[string]any{
			"org_id": orgID, "wrapped_for_archive_b64": wrapped, "account_archive_public_key": handoff.PublicKey, "grant_context": grantContext,
		}},
		"break-glass member regrant": {"/v1/archive/archive_unwrap_and_rewrap", map[string]any{
			"org_id": orgID, "wrapped_for_archive_b64": wrapped, "recipient_public_key": member.PublicKey,
			"owner_account_id": routeOwner, "recipient_account_id": routePeer, "grant_context": grantContext,
		}},
		"quorum combine": {"/v1/archive/archive_quorum_combine_and_rewrap", map[string]any{
			"grant_context": grantContext, "rewrapped_shares": []any{share, share},
			"wrapped_old_dek_b64": wrapped, "owner_account_id": routeOwner,
			"recipients": []any{map[string]any{"account_id": routePeer, "public_key": member.PublicKey}},
		}},
		"quorum split": {"/v1/archive/archive_key_split", map[string]any{
			"org_id": orgID, "threshold_n": 2,
			"recipient_public_keys": []string{routeKeypair(t).PublicKey, routeKeypair(t).PublicKey},
		}},
	} {
		code, result, body := callRoute(t, server, session, csrf, call.path, call.body)
		if (code == http.StatusOK && result.Success) || strings.Contains(body, "encrypted_for_other_b64") ||
			strings.Contains(body, "encrypted_group_dek_b64") || strings.Contains(body, "\"shares\"") {
			t.Fatalf("pre-authority App %s was accepted: %d %s", name, code, body)
		}
	}
}
