//go:build !windows

package handlers

import (
	"os"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// One signed exec policy runs one process. The fixture appends a line to a
// file each time it runs; after two submissions the file has one line.
func TestCredentialExec_SameSignedPolicyTwice_SecondStartsNoProcess(t *testing.T) {
	sh := credExecFixtureShell(t)
	dir := t.TempDir()
	marker := dir + "/runs"
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	nonce := mintCredentialNonce(t, deps)
	req := credExecRequest(t, groupRaw, handle, sh, []string{"-c", "echo run >> " + marker}, dir,
		func(r *proto.CredentialExecRequest) {
			r.Policy.PolicyVersion = proto.CredentialPolicyVersion
			r.Policy.ExecutionNonce = nonce
		})

	if first := HandleCredentialExecRequest(deps, req); !first.Success {
		t.Fatalf("first submission failed: %s (%s)", first.Error, first.ErrorCode)
	}
	requireRefused(t, HandleCredentialExecRequest(deps, req), errs.ErrCodeCredentialNonceInvalid)

	other := deps
	other.CredentialNonces = NewCredentialNonceStore()
	requireRefused(t, HandleCredentialExecRequest(other, req), errs.ErrCodeCredentialNonceInvalid)

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if runs := strings.Count(string(got), "run"); runs != 1 {
		t.Fatalf("the command ran %d times, want 1", runs)
	}
}

func TestCredentialExec_LegacyPolicyVersionStartsNoProcess(t *testing.T) {
	sh := credExecFixtureShell(t)
	dir := t.TempDir()
	marker := dir + "/ran"
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	nonce := mintCredentialNonce(t, deps)
	req := credExecRequest(t, groupRaw, handle, sh, []string{"-c", "touch " + marker}, dir,
		func(r *proto.CredentialExecRequest) {
			r.Policy.PolicyVersion = 1
			r.Policy.ExecutionNonce = nonce
		})
	requireRefused(t, HandleCredentialExecRequest(deps, req), errs.ErrCodeValidation)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a legacy-format policy started a process")
	}
}
