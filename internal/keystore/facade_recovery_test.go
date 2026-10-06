// facade_recovery_test.go: server-signature verification branch for
// Recovery-family actions. recoverysign must reject a bad server
// signature before any Keychain access or handle lookup (Recovery-context
// enforcement).
package keystore

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// TestHandleRequest_RecoverySign_BadServerSignature: even when the
// server public key is configured, a bad client-supplied signature must
// be rejected.
//
// old_private_key_pem is replaced by recovery_handle. Server-signature
// verification runs before handle lookup, so a fake handle is OK —
// rejection happens at the signature step first.
func TestHandleRequest_RecoverySign_BadServerSignature(t *testing.T) {
	app := newFacadeTestApp()
	if err := keychain.EnsureServerPublicKey(app.Store, app.Logger); err != nil {
		t.Fatalf("EnsureServerPublicKey: %v", err)
	}

	msg := `{"action":"recoverysign","payload":{
		"challenge_token":"some-token",
		"signature":"AAAA-not-a-valid-server-signature",
		"recovery_handle":"fake-handle"
	}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected recoverysign to fail with bad server signature")
	}
}

// TestHandleRequest_UnwrapGroupDEKWithKey_Unsupported: the legacy raw
// PEM Recovery path is no longer dispatched. Recovery rewrap must use
// recovery_session_open + dek_rewrap_with_old_key_to_self.
func TestHandleRequest_UnwrapGroupDEKWithKey_Unsupported(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"unwrapgroupdekwithkey","payload":{
		"challenge_token":"some-token",
		"signature":"AAAA-not-a-valid-server-signature",
		"old_private_key_pem":"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
		"encrypted_group_dek":"aGVsbG8="
	}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected unwrapgroupdekwithkey to be unsupported")
	}
	if resp.ErrorCode != "unsupported" {
		t.Fatalf("expected unsupported error_code, got %q (%s)", resp.ErrorCode, resp.Error)
	}
}
