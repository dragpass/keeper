package handlers

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

func TestCanonicalCredentialPolicyMatchesServerFormat(t *testing.T) {
	p := credTestPolicy([]string{"z.example", "a.example"}, []string{"POST", "GET"})
	got := canonicalCredentialPolicy(p)
	want := "entry_3|1|a.example,z.example|GET,POST|/*|13:Authorization23:Bearer {{secret.token}}|false|false|z.example|/x|POST|2100-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("canonical policy = %q, want %q", got, want)
	}
}

func TestPathAllowed(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		patterns []string
		want     bool
	}{
		{"exact", "https://api.example/v1/token", []string{"/v1/token"}, true},
		{"prefix", "https://api.example/v1/projects/42", []string{"/v1/projects/*"}, true},
		{"prefix boundary", "https://api.example/v10/projects/42", []string{"/v1/*"}, false},
		{"query ignored", "https://api.example/v1/token?scope=read", []string{"/v1/token"}, true},
		{"encoded distinct", "https://api.example/v1%2Fadmin", []string{"/v1/admin"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathAllowed(tt.target, tt.patterns); got != tt.want {
				t.Fatalf("pathAllowed()=%v want %v", got, tt.want)
			}
		})
	}
}

func TestCredentialRequestShapeAndHeaders(t *testing.T) {
	if requestShapeAllowed("https://api.example/v1?token=x", false, false, false) {
		t.Fatal("query must be denied when allow_query=false")
	}
	if requestShapeAllowed("https://api.example/v1", true, false, false) {
		t.Fatal("body must be denied when allow_body=false")
	}
	if !requestShapeAllowed("https://api.example/v1?scope=read", true, true, true) {
		t.Fatal("explicitly allowed query and body should pass")
	}
	signed := map[string]string{"Authorization": "Bearer {{secret.token}}"}
	if !headerTemplatesEqual(map[string]string{"Authorization": "Bearer {{secret.token}}"}, signed) {
		t.Fatal("identical signed header template should pass")
	}
	if headerTemplatesEqual(map[string]string{"Authorization": "Bearer {{secret.token}}", "X-Evil": "x"}, signed) {
		t.Fatal("additional header must fail closed")
	}
}

func TestVerifyCredentialPolicyRejectsExpiredPolicy(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.Clock = func() time.Time { return time.Date(2100, 1, 1, 0, 0, 1, 0, time.UTC) }
	p := credTestPolicy([]string{"api.example"}, []string{"GET"})
	ok, resp := verifyCredentialPolicy(deps, []byte(credTestAAD), p)
	if ok || resp.Success {
		t.Fatal("expired policy must fail closed")
	}
}

func TestVerifyCredentialPolicyRejectsAADBindingMismatch(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	p := credTestPolicy([]string{"api.example"}, []string{"GET"})
	ok, resp := verifyCredentialPolicy(deps, []byte("org_9|other_entry|credential|1|1"), p)
	if ok || resp.Success {
		t.Fatal("policy entry mismatch must fail closed")
	}
}

func TestVerifyCredentialPolicyRejectsBadServerSignature(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.ServerKeyVerifier = verifier.AlwaysFailVerifier{Err: errors.New("bad signature")}
	p := credTestPolicy([]string{"api.example"}, []string{"GET"})
	ok, resp := verifyCredentialPolicy(deps, []byte(credTestAAD), p)
	if ok || resp.Success {
		t.Fatal("invalid server signature must fail closed")
	}
}

func TestCredentialPolicyValidateRequiresSignatureEnvelope(t *testing.T) {
	req := proto.CredentialHTTPRequest{
		GroupHandle:    strings.Repeat("A", 32),
		IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64:  base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		AADB64:         base64.StdEncoding.EncodeToString([]byte(credTestAAD)),
		TargetURL:      "https://api.example/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy: proto.CredentialPolicy{
			EntryID: "entry_3", DekVersion: 1,
			AllowedHosts: []string{"api.example"}, AllowedMethods: []string{"GET"},
			AllowedPathPatterns: []string{"/v1/*"},
			HeaderTemplate:      map[string]string{"Authorization": "Bearer {{secret.token}}"},
			TargetHost:          "api.example",
			TargetPath:          "/x",
			Method:              "GET",
			Expiry:              "2100-01-01T00:00:00Z", ServerKeyVersion: 1,
			SignatureAlg: credentialPolicySignatureAlg,
		},
	}
	if err := req.Validate(); err == nil {
		t.Fatal("unsigned credential policy must fail validation")
	}
}
