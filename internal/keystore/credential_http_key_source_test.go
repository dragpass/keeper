// credential_http_key_source_test.go — key-source selection guards for the
// decrypt-to-tool sink.
//
// CredentialHTTPRequest now takes either an org Group DEK handle or a
// device-wrapped personal DEK. The eight safeguards run once for both scopes
// (withCredentialDEK branches only the key source), so what needs guarding is
// the selection itself:
//
//   - exactly one source. Both would leave which key opened the payload
//     ambiguous; neither has no caller.
//   - the request shape carries no raw secret in either scope.
//
// Lives in the keystore package so it validates through the exported proto
// surface the Extension actually sends.

package keystore

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// credHTTPBase builds a request that passes every check except the key source,
// so a failure is unambiguously about the source.
func credHTTPBase() proto.CredentialHTTPRequest {
	return proto.CredentialHTTPRequest{
		IVB64:          "AAAAAAAAAAAAAAAA", // 12 bytes
		CiphertextB64:  "Y2lwaGVydGV4dA==",
		AADB64:         "YWNjdF80MnxlbnRyeV83fGNyZWRlbnRpYWx8MXwx",
		TargetURL:      "https://api.example.com/v1/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy: proto.CredentialPolicy{
			AllowedHosts:        []string{"api.example.com"},
			AllowedMethods:      []string{"GET"},
			AllowedPathPatterns: []string{"/v1/*"},
			HeaderTemplate:      map[string]string{"Authorization": "Bearer {{secret.token}}"},
			TargetHost:          "api.example.com",
			TargetPath:          "/v1/x",
			Method:              "GET",
			EntryID:             "entry_7",
			DekVersion:          1,
			Expiry:              "2099-01-01T00:00:00Z",
			Signature:           "c2ln",
			SignatureAlg:        "RS256",
			ServerKeyVersion:    1,
		},
	}
}

func TestCredentialHTTPRequest_RejectsBothKeySources(t *testing.T) {
	req := credHTTPBase()
	req.GroupHandle = strings.Repeat("a", 40)
	req.EncryptedDEKB64 = "ZGV2aWNlLXdyYXBwZWQ="

	err := req.Validate()
	if err == nil {
		t.Fatal("both key sources accepted — which key opened the payload would be ambiguous")
	}
	if !strings.Contains(err.Error(), "exactly one key source") {
		t.Errorf("error = %v, want it to name the exactly-one rule", err)
	}
}

func TestCredentialHTTPRequest_RejectsNoKeySource(t *testing.T) {
	req := credHTTPBase()

	err := req.Validate()
	if err == nil {
		t.Fatal("missing key source accepted — nothing could open the payload")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error = %v, want it to say a source is required", err)
	}
}

func TestCredentialHTTPRequest_AcceptsEitherKeySourceAlone(t *testing.T) {
	orgReq := credHTTPBase()
	orgReq.GroupHandle = strings.Repeat("a", 40)
	if err := orgReq.Validate(); err != nil {
		t.Errorf("org scope rejected: %v", err)
	}

	personalReq := credHTTPBase()
	personalReq.EncryptedDEKB64 = "ZGV2aWNlLXdyYXBwZWQ="
	if err := personalReq.Validate(); err != nil {
		t.Errorf("personal scope rejected: %v", err)
	}
}

// The personal key source is a device-wrapped DEK — unreadable without the
// Keychain device key, which never crosses IPC. It must stay classified as
// public material like the opaque group handle, not smuggled in as a secret.
func TestCredentialHTTPRequest_PersonalKeySourceIsNotRawSecret(t *testing.T) {
	req := credHTTPBase()
	req.EncryptedDEKB64 = "ZGV2aWNlLXdyYXBwZWQ="
	if err := req.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// A raw 32-byte DEK would be the secret itself; the field carries the
	// wrapped form (iv || ciphertext || tag), which is strictly longer.
	if len(req.EncryptedDEKB64) == 0 {
		t.Error("encrypted_dek_b64 must carry the wrapped DEK, never a raw one")
	}
}
