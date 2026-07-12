// archive_key_test.go — regression guard for the per-org archive keypair.
//
//   - HandleArchiveKeyGenerate creates an RSA archive keypair when none exists
//     and is idempotent on repeated calls (same public key + fingerprint).
//   - HandleArchiveKeyStatus returns has_active=false before generate, true
//     after.
//   - The archive private key must never be echoed to the logger or the
//     response error (security requirement — it lives only in its keychain
//     slot).

package handlers

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleArchiveKeyGenerate_CreatesAndIdempotent(t *testing.T) {
	deps, log, store := newTestDeps(t)

	resp1 := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{})
	if !resp1.Success {
		t.Fatalf("first generate failed: %s", resp1.Error)
	}
	data1, ok := resp1.Data.(proto.ArchiveKeyGenerateResponseData)
	if !ok {
		t.Fatalf("unexpected response type: %T", resp1.Data)
	}
	if data1.PublicKey == "" || data1.Fingerprint == "" {
		t.Errorf("publickey / fingerprint must be set: %+v", data1)
	}
	if !strings.Contains(data1.PublicKey, "PUBLIC KEY") {
		t.Errorf("public key must be PEM, got %q", data1.PublicKey)
	}

	// The private key must be stored in its own slot.
	priv, err := keychain.GetArchivePrivateKey(store)
	if err != nil || priv == "" {
		t.Fatalf("archive private key not stored: %v", err)
	}
	if !strings.Contains(priv, "PRIVATE KEY") {
		t.Errorf("stored archive private key must be PEM")
	}

	// The second call returns the same key meta (idempotent).
	resp2 := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{})
	if !resp2.Success {
		t.Fatalf("second generate failed: %s", resp2.Error)
	}
	data2, _ := resp2.Data.(proto.ArchiveKeyGenerateResponseData)
	if data2.PublicKey != data1.PublicKey || data2.Fingerprint != data1.Fingerprint {
		t.Errorf("idempotent generate should return same key: %q/%q vs %q/%q",
			data2.PublicKey, data2.Fingerprint, data1.PublicKey, data1.Fingerprint)
	}
	if !log.Contains("active key already present") {
		t.Errorf("expected idempotent log branch, got %v", log.Messages())
	}
}

func TestHandleArchiveKeyStatus_ReflectsPresence(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	before := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{})
	if b, _ := before.Data.(proto.ArchiveKeyStatusResponseData); b.HasActive {
		t.Fatalf("expected has_active=false before generate")
	}

	if r := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{}); !r.Success {
		t.Fatalf("generate failed: %s", r.Error)
	}

	after := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{})
	a, _ := after.Data.(proto.ArchiveKeyStatusResponseData)
	if !a.HasActive || a.PublicKey == "" || a.Fingerprint == "" {
		t.Fatalf("expected active archive key after generate: %+v", a)
	}
}

func TestHandleArchiveKeyGenerate_DoesNotLeakPrivateKey(t *testing.T) {
	deps, log, store := newTestDeps(t)

	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{})
	if !resp.Success {
		t.Fatalf("generate failed: %s", resp.Error)
	}

	priv, err := keychain.GetArchivePrivateKey(store)
	if err != nil || priv == "" {
		t.Fatalf("archive private key not stored: %v", err)
	}

	// Guard each base64 body line of the stored private key against the logger
	// and the response error string.
	for line := range strings.SplitSeq(priv, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 40 || strings.Contains(line, "PRIVATE KEY") {
			continue
		}
		if log.Contains(line) {
			t.Fatalf("logger leaked archive private key material: %v", log.Messages())
		}
		if strings.Contains(resp.Error, line) {
			t.Fatalf("response error leaked archive private key material")
		}
	}
}
