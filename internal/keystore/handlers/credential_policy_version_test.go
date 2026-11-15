package handlers

import (
	"strconv"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// credVersionTestPolicy is a policy that passes every check after the version
// check, so the version alone decides the outcome.
func credVersionTestPolicy(version int) proto.CredentialPolicy {
	p := credTestPolicy([]string{"api.example"}, []string{"GET"})
	p.PolicyVersion = version
	p.ExecutionNonce = strings.Repeat("A", proto.CredentialExecutionNonceChars)
	p.PayloadSHA256 = strings.Repeat("a", 64)
	return p
}

// TestVerifyCredentialPolicy_RefusalNamesTheAcceptedVersion pins that the
// refusal names the version Keeper actually accepts. The expected text is
// derived from proto.CredentialPolicyVersion so it cannot drift from it.
func TestVerifyCredentialPolicy_RefusalNamesTheAcceptedVersion(t *testing.T) {
	want := "credential policy version is not supported; only policy_version " +
		strconv.Itoa(proto.CredentialPolicyVersion) + " is accepted"
	for _, version := range []int{
		proto.CredentialPolicyVersion - 2,
		proto.CredentialPolicyVersion - 1,
		proto.CredentialPolicyVersion + 1,
	} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			deps, _, _ := newTestDeps(t)
			ok, resp := verifyCredentialPolicy(deps, []byte(credTestAAD), credVersionTestPolicy(version))
			if ok || resp.Success {
				t.Fatalf("policy_version %d was accepted", version)
			}
			if resp.ErrorCode != string(errs.ErrCodeValidation) {
				t.Fatalf("error_code = %q, want %q", resp.ErrorCode, errs.ErrCodeValidation)
			}
			if resp.Error != want {
				t.Fatalf("error = %q, want %q", resp.Error, want)
			}
		})
	}
}

func TestVerifyCredentialPolicy_AcceptsTheCurrentVersion(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	ok, resp := verifyCredentialPolicy(deps, []byte(credTestAAD), credVersionTestPolicy(proto.CredentialPolicyVersion))
	if !ok {
		t.Fatalf("policy_version %d was refused: %s %s", proto.CredentialPolicyVersion, resp.ErrorCode, resp.Error)
	}
}
