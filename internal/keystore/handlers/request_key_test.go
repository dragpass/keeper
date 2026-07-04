// request_key_test.go — regression guard.
//
//   - HandleRequestKeyGenerate creates a new Ed25519 keypair when no active
//     key exists and is idempotent on repeated calls.
//   - HandleRequestKeyStatus returns has_active=false before enroll, true after.
//   - HandleSignRequest signs canonical_request with the active key, produces
//     a reproducible signature for the same input, and returns not_found when
//     no active key exists.
//   - canonical_request must not be echoed to the logger (security requirement).

package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleRequestKeyGenerate_CreatesAndIdempotent(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp1 := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !resp1.Success {
		t.Fatalf("first generate failed: %s", resp1.Error)
	}
	data1, ok := resp1.Data.(proto.RequestKeyGenerateResponseData)
	if !ok {
		t.Fatalf("unexpected response type: %T", resp1.Data)
	}
	if data1.PublicKey == "" || data1.Fingerprint == "" {
		t.Errorf("publickey / fingerprint must be set: %+v", data1)
	}
	rawPub, err := base64.StdEncoding.DecodeString(data1.PublicKey)
	if err != nil {
		t.Fatalf("public key decode: %v", err)
	}
	if len(rawPub) != ed25519.PublicKeySize {
		t.Errorf("pub size = %d want %d", len(rawPub), ed25519.PublicKeySize)
	}

	// The second call returns the same key meta (idempotent).
	resp2 := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !resp2.Success {
		t.Fatalf("second generate failed: %s", resp2.Error)
	}
	data2, _ := resp2.Data.(proto.RequestKeyGenerateResponseData)
	if data2.PublicKey != data1.PublicKey {
		t.Errorf("idempotent generate should return same key, got %q vs %q",
			data2.PublicKey, data1.PublicKey)
	}

	// The second call must take the "active key already present" branch.
	if !log.Contains("active key already present") {
		t.Errorf("expected idempotent log branch, got %v", log.Messages())
	}
}

func TestHandleRequestKeyStatus_NoneThenPresent(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleRequestKeyStatus(deps, proto.RequestKeyStatusRequest{})
	if !resp.Success {
		t.Fatalf("status (no key) failed: %s", resp.Error)
	}
	data, _ := resp.Data.(proto.RequestKeyStatusResponseData)
	if data.HasActive {
		t.Error("has_active should be false before enroll")
	}

	// After generate, status=true.
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate failed: %s", r.Error)
	}

	resp2 := HandleRequestKeyStatus(deps, proto.RequestKeyStatusRequest{})
	data2, _ := resp2.Data.(proto.RequestKeyStatusResponseData)
	if !data2.HasActive {
		t.Error("has_active should be true after enroll")
	}
	if data2.PublicKey == "" || data2.Fingerprint == "" {
		t.Errorf("status should include public key and fingerprint, got %+v", data2)
	}
}

func TestHandleSignRequest_RoundTrip(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	gen := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{})
	if !gen.Success {
		t.Fatalf("generate failed: %s", gen.Error)
	}
	pubData, _ := gen.Data.(proto.RequestKeyGenerateResponseData)

	canonical := "dp-req-v1\nPOST\n/api/v1/x\n\n1700000000\nnonce-1\n0\nacct\ntok\ndev"
	resp := HandleSignRequest(deps, proto.SignRequestRequest{CanonicalRequest: canonical})
	if !resp.Success {
		t.Fatalf("sign failed: %s", resp.Error)
	}
	data, _ := resp.Data.(proto.SignRequestResponseData)
	if data.Signature == "" {
		t.Fatal("signature must not be empty")
	}

	rawSig, err := base64.StdEncoding.DecodeString(data.Signature)
	if err != nil {
		t.Fatalf("signature base64: %v", err)
	}
	if len(rawSig) != ed25519.SignatureSize {
		t.Errorf("sig size = %d want %d", len(rawSig), ed25519.SignatureSize)
	}
	rawPub, _ := base64.StdEncoding.DecodeString(pubData.PublicKey)
	if !ed25519.Verify(rawPub, []byte(canonical), rawSig) {
		t.Error("signature failed Ed25519 verification with returned public key")
	}

	// Security regression: canonical_request must not be echoed to the logger.
	for _, msg := range log.Messages() {
		if strings.Contains(msg, canonical) {
			t.Errorf("canonical_request must not be echoed in logs: %q", msg)
		}
	}
}

func TestHandleSignRequest_NoActiveKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandleSignRequest(deps, proto.SignRequestRequest{
		CanonicalRequest: "dp-req-v1\nGET\n/x\n\n1\nn\n0\na\nt\nd",
	})
	if resp.Success {
		t.Error("sign should fail with no active key")
	}
	if !strings.Contains(resp.Error, "request signing key not found") {
		t.Errorf("expected not_found error, got %q", resp.Error)
	}
}

func TestHandleSignRequest_EmptyCanonical(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	if r := HandleRequestKeyGenerate(deps, proto.RequestKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate: %s", r.Error)
	}
	resp := HandleSignRequest(deps, proto.SignRequestRequest{CanonicalRequest: ""})
	if resp.Success {
		t.Error("empty canonical_request should be rejected")
	}
}
