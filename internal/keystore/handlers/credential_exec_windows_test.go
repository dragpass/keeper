//go:build windows

// credential_exec_windows_test.go — the exec sink is refused on Windows.
//
// Windows has no counterpart to Setpgid + kill(-pgid). Killing a tree needs a
// Job Object created and assigned before the child starts, and until that exists
// a timeout here would kill the direct child and leave any grandchild running
// with the injected credential still in its environment. A safeguard that does
// not work must not be presented as one, so the handler refuses the whole action
// rather than running it with a timeout that half-applies.
//
// What this file pins is that the refusal comes *first* — before the sealed
// payload is decoded, before the policy signature is checked, before Validate.
// If the platform gate ever drifts below one of those, a Windows caller would
// start getting validation errors instead of "unsupported", and the version gate
// on the caller's side (which keys on this code) would stop working.

package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestCredentialExec_UnsupportedOnWindows — a well-formed request is refused
// with ErrCodeUnsupported.
func TestCredentialExec_UnsupportedOnWindows(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	req := credExecRequest(t, groupRaw, handle,
		"/usr/bin/gh", []string{"api", "user"}, "/tmp/work", nil)

	resp := HandleCredentialExecRequest(deps, req)
	if resp.Success {
		t.Fatal("credential_exec_request succeeded on a platform with no process-group kill")
	}
	if resp.ErrorCode != string(errs.ErrCodeUnsupported) {
		t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeUnsupported)
	}
	if !strings.Contains(resp.Error, "not supported on this platform") {
		t.Errorf("error = %q, want it to name the platform", resp.Error)
	}

	// The sealed payload was never opened, so nothing it carries can appear in
	// the response or the log.
	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), credExecSecret) {
		t.Fatalf("refused request leaked the sealed secret: %s", respJSON)
	}
	if log.Contains(credExecSecret) {
		t.Fatal("refused request leaked the sealed secret into the log")
	}
}

// TestCredentialExec_UnsupportedBeforeValidation — the platform gate runs before
// Validate. A request that Validate would reject (no key source at all) still
// comes back as unsupported, which is how we know nothing downstream of the gate
// ran.
func TestCredentialExec_UnsupportedBeforeValidation(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleCredentialExecRequest(deps, proto.CredentialExecRequest{})
	if resp.Success {
		t.Fatal("an empty credential_exec_request succeeded")
	}
	if resp.ErrorCode != string(errs.ErrCodeUnsupported) {
		t.Fatalf("error_code = %q, want %q — the platform gate must run before Validate",
			resp.ErrorCode, errs.ErrCodeUnsupported)
	}
}
