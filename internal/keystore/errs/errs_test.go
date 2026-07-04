// Error Taxonomy — regression guards for ErrorCode mapping + response
// helpers. Lives in the errs/ subpackage (relocated from keystore root).
//
// **Defects this test catches:**
//   - Regressions where a new sentinel was added but not mapped in
//     CodeForError
//   - Regressions where Response drops or transforms the input err's message
//   - Regressions where BaseResponse.ErrorCode breaks during serialization /
//     deserialization
//
// The recovery_session_actions worked example remains in keystore root
// (the App method calls depend on the root package's NewApp / Deps /
// AlwaysFailVerifier).
package errs

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

func TestCodeForError_Validation(t *testing.T) {
	err := &proto.ValidationError{Field: "group_handle", Reason: "must not be empty"}
	if got := CodeForError(err); got != ErrCodeValidation {
		t.Fatalf("expected validation_error, got %q", got)
	}
}

func TestCodeForError_NotFound(t *testing.T) {
	cases := []error{
		keychain.ErrSecretNotFound,
		keychain.ErrServerKeyVersionNotFound,
		keychain.ErrNoActiveServerKey,
		sessions.ErrRecoverySessionNotFound,
		sessions.ErrGroupSessionNotFound,
	}
	for _, c := range cases {
		if got := CodeForError(c); got != ErrCodeNotFound {
			t.Fatalf("err=%v: expected not_found, got %q", c, got)
		}
	}
}

func TestCodeForError_ExpiredSession(t *testing.T) {
	cases := []error{sessions.ErrRecoverySessionExpired, sessions.ErrGroupSessionExpired}
	for _, c := range cases {
		if got := CodeForError(c); got != ErrCodeExpiredSession {
			t.Fatalf("err=%v: expected expired_session, got %q", c, got)
		}
	}
}

func TestCodeForError_UnknownIsInternal(t *testing.T) {
	err := errors.New("some random non-sentinel error")
	if got := CodeForError(err); got != ErrCodeInternal {
		t.Fatalf("expected internal_error, got %q", got)
	}
}

func TestCodeForError_NilIsEmpty(t *testing.T) {
	if got := CodeForError(nil); got != "" {
		t.Fatalf("expected empty string for nil, got %q", got)
	}
}

func TestResponse_PreservesMessage(t *testing.T) {
	err := errors.New("expected message body")
	resp := Response(err)
	if resp.Success {
		t.Fatalf("Response must produce success=false")
	}
	if resp.Error != "expected message body" {
		t.Fatalf("error message dropped: got %q", resp.Error)
	}
	if resp.ErrorCode != string(ErrCodeInternal) {
		t.Fatalf("expected internal_error code, got %q", resp.ErrorCode)
	}
}

func TestResponse_NilProducesEmpty(t *testing.T) {
	resp := Response(nil)
	if resp.Success || resp.Error != "" || resp.ErrorCode != "" {
		t.Fatalf("nil err must produce empty failure envelope, got %+v", resp)
	}
}

func TestCodeResponse_AssignsExplicitCode(t *testing.T) {
	resp := CodeResponse(ErrCodeCryptoFailure, "decrypt failed: wrong key")
	if resp.Success {
		t.Fatalf("must be failure")
	}
	if resp.ErrorCode != "crypto_failure" {
		t.Fatalf("expected crypto_failure, got %q", resp.ErrorCode)
	}
	if resp.Error != "decrypt failed: wrong key" {
		t.Fatalf("message dropped: %q", resp.Error)
	}
}

// TestBaseResponse_ErrorCodeOmitemptyOnSuccess: success=true responses must
// not serialize error_code (omitempty). Regression guard for older Extension
// strict JSON parser compatibility.
func TestBaseResponse_ErrorCodeOmitemptyOnSuccess(t *testing.T) {
	resp := proto.BaseResponse{Success: true, Data: proto.PingResponseData{Version: "1.0"}}
	bytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(bytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["error_code"]; ok {
		t.Fatalf("error_code must be omitted on success, got %s", string(bytes))
	}
}

// TestBaseResponse_ErrorCodeOmittedWhenEmpty: even when success=false, an
// empty ErrorCode is omitted from serialization (legacy handler compat).
func TestBaseResponse_ErrorCodeOmittedWhenEmpty(t *testing.T) {
	resp := proto.BaseResponse{Success: false, Error: "legacy error msg"}
	bytes, _ := json.Marshal(resp)
	var raw map[string]any
	_ = json.Unmarshal(bytes, &raw)
	if _, ok := raw["error_code"]; ok {
		t.Fatalf("empty error_code must be omitted, got %s", string(bytes))
	}
}
