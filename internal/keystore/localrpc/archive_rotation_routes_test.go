package localrpc

import (
	"net/http"
	"testing"
)

func TestRotationRoutesRefuseCallerSuppliedTarget(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	for _, path := range []string{"/v1/archive/archive_quorum_rotation_prepare", "/v1/archive/archive_quorum_combine_to_staged"} {
		status, _, _ := callRoute(t, server, session, csrf, path, map[string]any{"request": map[string]any{"target_public_key": "client-supplied"}})
		if status != http.StatusBadRequest {
			t.Fatalf("route %s accepted an unknown recipient field: HTTP %d", path, status)
		}
	}
}
