// Tests for the payload binding of the signed credential policy (lv84 L2):
// a policy names the exact sealed payload it was issued for, so an older
// ciphertext presented with a newer policy is never opened. Test values are
// compared in memory and never printed.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// payloadDigestForTest is the lowercase hex SHA-256 of IV || ciphertext.
func payloadDigestForTest(t *testing.T, ivB64, ctB64 string) string {
	t.Helper()
	iv, err1 := base64.StdEncoding.DecodeString(ivB64)
	ct, err2 := base64.StdEncoding.DecodeString(ctB64)
	if err1 != nil || err2 != nil {
		t.Fatal("payload is not base64")
	}
	sum := sha256.Sum256(append(append([]byte(nil), iv...), ct...))
	return hex.EncodeToString(sum[:])
}

func TestCredentialHTTP_OpensOnlyThePayloadThePolicyNames(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	s := newSingleUseServer(t, nil)

	ok := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
	if resp := HandleCredentialHTTPRequest(deps, ok); !resp.Success || s.hits.Load() != 1 {
		t.Fatalf("a request for the named payload failed: %s", resp.ErrorCode)
	}

	nonce := mintCredentialNonce(t, deps)
	stale := singleUseRequest(t, deps, s, "", nil, nonce)
	// Another sealed payload of the same item: the policy still names the
	// one it was issued for.
	other := singleUseRequest(t, deps, s, "", nil, nonce)
	stale.IVB64, stale.CiphertextB64 = other.IVB64, other.CiphertextB64
	stale.GroupHandle = other.GroupHandle
	resp := HandleCredentialHTTPRequest(deps, stale)
	requireRefused(t, resp, errs.ErrCodeCryptoFailure)
	if s.hits.Load() != 1 {
		t.Fatal("a payload the policy does not name reached the target")
	}
	// Refused before the nonce was spent.
	retry := singleUseRequest(t, deps, s, "", nil, nonce)
	if resp := HandleCredentialHTTPRequest(deps, retry); !resp.Success {
		t.Fatalf("the nonce was spent by the refused request: %s", resp.ErrorCode)
	}
}

func TestCredentialPolicy_RequiresAPayloadDigest(t *testing.T) {
	p := credTestPolicy([]string{"api.example.com"}, []string{"GET"})
	p.PolicyVersion = proto.CredentialPolicyVersion
	p.ExecutionNonce = "Zm9vYmFyLWNyZWRlbnRpYWwtbm9uY2UtZml4dHVyZTA"
	p.PayloadSHA256 = ""
	deps, _, _ := newTestDeps(t)
	if ok, _ := verifyCredentialPolicy(deps, []byte(credTestAAD), p); ok {
		t.Fatal("a policy without a payload digest was accepted")
	}
}
