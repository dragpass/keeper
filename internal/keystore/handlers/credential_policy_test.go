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

// credSharedFixturePolicy — ariadne 의 sign_test.go 가 같은 값으로 같은 문자열을
// 만드는지 확인하는 공유 fixture. 두 저장소의 canonical 이 한 자리라도 어긋나면
// 모든 resolve 의 서명이 깨지므로, 기대값은 헬퍼를 부르지 않고 리터럴로 적는다.
func credSharedFixturePolicy() proto.CredentialPolicy {
	return proto.CredentialPolicy{
		EntryID:             "11111111-1111-1111-1111-111111111111",
		DekVersion:          3,
		AllowedHosts:        []string{"api.example.com"},
		AllowedMethods:      []string{"POST", "GET"},
		AllowedPathPatterns: []string{"/v1/*"},
		HeaderTemplate:      map[string]string{"X-API-Key": "{{secret.token}}"},
		TargetHost:          "api.example.com",
		TargetPath:          "/v1/users",
		Method:              "GET",
		ApprovalMode:        "always_ask",
		Expiry:              "2026-07-18T12:00:00Z",
	}
}

// TestCanonicalCredentialPolicy_SharedFixture — 공유 fixture 의 현재 canonical.
// 이 리터럴이 바뀌면 이미 배포된 서버가 서명한 정책을 Keeper 가 더는 검증하지
// 못한다는 뜻이다.
func TestCanonicalCredentialPolicy_SharedFixture(t *testing.T) {
	got := canonicalCredentialPolicy(credSharedFixturePolicy())
	want := "11111111-1111-1111-1111-111111111111|3|api.example.com|GET,POST|/v1/*|" +
		"9:X-API-Key16:{{secret.token}}|false|false|api.example.com|/v1/users|GET|" +
		"2026-07-18T12:00:00Z"
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
