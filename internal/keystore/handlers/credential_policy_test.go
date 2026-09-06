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

// TestCanonicalCredentialPolicy_SharedFixtureWithQueryTemplate — 같은 fixture 에
// query 주입만 얹은 판. 앞 테스트의 문자열에 자리가 하나 붙고 header 자리는 빈
// 문자열이 된다. ariadne sign_test.go 에 같은 리터럴이 있다.
func TestCanonicalCredentialPolicy_SharedFixtureWithQueryTemplate(t *testing.T) {
	p := credSharedFixturePolicy()
	p.HeaderTemplate = map[string]string{}
	p.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}
	got := canonicalCredentialPolicy(p)
	want := "11111111-1111-1111-1111-111111111111|3|api.example.com|GET,POST|/v1/*|" +
		"|false|false|api.example.com|/v1/users|GET|" +
		"2026-07-18T12:00:00Z|7:api_key16:{{secret.token}}"
	if got != want {
		t.Fatalf("canonical policy = %q, want %q", got, want)
	}
}

// TestCanonicalCredentialPolicy_EmptyQueryTemplateKeepsOldFormat — nil 과 빈 map
// 은 자리를 만들지 않는다. 여기가 깨지면 기존 credential 의 서명이 전부 깨진다.
func TestCanonicalCredentialPolicy_EmptyQueryTemplateKeepsOldFormat(t *testing.T) {
	base := canonicalCredentialPolicy(credSharedFixturePolicy())
	empty := credSharedFixturePolicy()
	empty.QueryTemplate = map[string]string{}
	if got := canonicalCredentialPolicy(empty); got != base {
		t.Fatalf("빈 query_template 이 canonical 을 바꿨다: %q, want %q", got, base)
	}
}

// credSharedExecFixturePolicy — exec 정책의 공유 fixture. HTTP 세 목록이 비고
// header / query template 도 비며, 대신 서명이 명령 한 벌 (executable / argv /
// cwd) 과 env_template 을 묶는다. ariadne sign_test.go 에 같은 값이 있다.
func credSharedExecFixturePolicy() proto.CredentialPolicy {
	return proto.CredentialPolicy{
		EntryID:        "11111111-1111-1111-1111-111111111111",
		DekVersion:     3,
		HeaderTemplate: map[string]string{},
		ExecExecutable: "/usr/bin/gh",
		ExecArgv:       []string{"/usr/bin/gh", "api", "user"},
		ExecCwd:        "/tmp/work",
		EnvTemplate:    map[string]string{"GH_TOKEN": "{{secret.token}}"},
		ApprovalMode:   "always_ask",
		Expiry:         "2026-07-18T12:00:00Z",
	}
}

// TestCanonicalCredentialPolicy_SharedExecFixture — exec 정책의 현재 canonical.
// ariadne 의 TestCanonicalPolicyString_SharedExecFixture 가 같은 리터럴을 만든다.
// 두 저장소가 한 자리라도 어긋나면 모든 exec resolve 의 서명 검증이 깨진다.
func TestCanonicalCredentialPolicy_SharedExecFixture(t *testing.T) {
	got := canonicalCredentialPolicy(credSharedExecFixturePolicy())
	want := "11111111-1111-1111-1111-111111111111|3|||||false|false||||" +
		"2026-07-18T12:00:00Z|/usr/bin/gh|11:/usr/bin/gh,3:api,4:user|/tmp/work|" +
		"8:GH_TOKEN16:{{secret.token}}"
	if got != want {
		t.Fatalf("canonical policy = %q, want %q", got, want)
	}
}

// TestCanonicalCredentialPolicy_ExecFieldsDoNotTouchHTTPPolicies — exec 필드가
// 생긴 뒤에도 HTTP 정책의 canonical 은 바이트 단위로 같다. 0.0.27 이 서명 검증
// 하던 문자열이 그대로여야 옛 서버가 서명한 정책이 계속 검증된다.
func TestCanonicalCredentialPolicy_ExecFieldsDoNotTouchHTTPPolicies(t *testing.T) {
	base := canonicalCredentialPolicy(credSharedFixturePolicy())
	const want = "11111111-1111-1111-1111-111111111111|3|api.example.com|GET,POST|/v1/*|" +
		"9:X-API-Key16:{{secret.token}}|false|false|api.example.com|/v1/users|GET|" +
		"2026-07-18T12:00:00Z"
	if base != want {
		t.Fatalf("HTTP canonical = %q, want %q", base, want)
	}
	// 빈 exec 필드는 자리를 만들지 않는다 — nil 도 빈 map 도.
	empty := credSharedFixturePolicy()
	empty.EnvTemplate = map[string]string{}
	empty.ExecExecutable = ""
	empty.ExecArgv = nil
	empty.ExecCwd = ""
	if got := canonicalCredentialPolicy(empty); got != base {
		t.Fatalf("빈 exec 필드가 canonical 을 바꿨다: %q, want %q", got, base)
	}
}

// TestCanonicalCredentialArgv_LengthPrefixIsInjective — 길이 접두가 쉼표와
// 파이프를 담은 인자를 자기 구획 안에 가둔다. 접두가 없으면 서로 다른 argv 가
// 같은 문자열로 서명될 수 있다.
func TestCanonicalCredentialArgv_LengthPrefixIsInjective(t *testing.T) {
	a := canonicalCredentialArgv([]string{"a,b", "c"})
	b := canonicalCredentialArgv([]string{"a", "b,c"})
	if a == b {
		t.Fatalf("쉼표를 담은 argv 가 같은 canonical 이 됐다: %q", a)
	}
	if got := canonicalCredentialArgv([]string{"a,b", "c"}); got != "3:a,b,1:c" {
		t.Fatalf("argv canonical = %q", got)
	}
	if got := canonicalCredentialArgv(nil); got != "" {
		t.Fatalf("빈 argv canonical = %q, want \"\"", got)
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
