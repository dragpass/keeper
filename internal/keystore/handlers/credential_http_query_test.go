// credential_http_query_test.go — the query_template injection surface.
//
// A credential that goes out as a query parameter is a weaker posture than one
// that goes out as a header: it lands in the target's access log and in every
// proxy between here and there. What the Keeper can still guarantee is the part
// on this side of the wire, and that is what these tests pin down:
//
//   - the rendered value is appended to target_url's query and reaches the
//     server, while target_url itself is never template-substituted;
//   - a parameter the caller already put in target_url is refused rather than
//     duplicated (which of the two the server reads is not ours to decide);
//   - a query_template that differs from the signed one is refused before any
//     bytes go out;
//   - the secret echoed back — raw or percent-encoded, which is how it appears
//     in a query string — is masked;
//   - the URL carrying the secret never reaches the IPC response, not even
//     through a transport error, which embeds it verbatim in *url.Error.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"crypto/tls"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// credQuerySecret carries characters a query string must percent-encode, so the
// redaction assertions exercise the encoded variant and not just the literal.
const credQuerySecret = "SUPER_SECRET/TOKEN+XYZ"

type observedQuery struct {
	rawQuery string
	apiKey   string
	headers  http.Header
}

// credQueryRoundTrip drives a full request whose policy injects into the query.
// mutate (optional) adjusts the request just before it is handled, which is how
// the fail-closed cases diverge from the happy path.
func credQueryRoundTrip(
	t *testing.T,
	serverHandler http.HandlerFunc,
	mutate func(*proto.CredentialHTTPRequest),
) (proto.BaseResponse, *observedQuery, *logger.MemoryLogger) {
	t.Helper()

	obs := &observedQuery{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.rawQuery = r.URL.RawQuery
		obs.apiKey = r.URL.Query().Get("api_key")
		obs.headers = r.Header.Clone()
		serverHandler(w, r)
	}))
	t.Cleanup(ts.Close)

	prev := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		cfg.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true
	t.Cleanup(func() { testTLSConfigHook = prev; testAllowLoopbackDial = prevLoopback })

	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"`+credQuerySecret+`"}}`, credTestAAD)

	queryTemplate := map[string]string{"api_key": "{{secret.token}}"}
	policy := credTestPolicy([]string{hostOf(t, ts.URL)}, []string{"GET"})
	policy.HeaderTemplate = map[string]string{}
	policy.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}

	req := proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      ts.URL + "/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{},
		QueryTemplate:  queryTemplate,
		Policy:         policy,
	}
	if mutate != nil {
		mutate(&req)
	}
	return HandleCredentialHTTPRequest(deps, req), obs, log
}

// assertNoSecretAnywhere fails when the secret, its percent-encoded form, or the
// injected parameter reaches the IPC response or the logger.
func assertNoSecretAnywhere(t *testing.T, resp proto.BaseResponse, log *logger.MemoryLogger) {
	t.Helper()
	serialized, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	surfaces := map[string]string{"IPC response": string(serialized)}
	if log != nil {
		surfaces["logger"] = strings.Join(log.Messages(), "\n")
	}
	for name, text := range surfaces {
		for _, needle := range []string{
			credQuerySecret,
			url.QueryEscape(credQuerySecret),
			"api_key=",
		} {
			if strings.Contains(text, needle) {
				t.Fatalf("%s leaked %q: %s", name, needle, text)
			}
		}
	}
}

func TestCredentialHTTP_QueryTemplate_AppendedToURL(t *testing.T) {
	resp, obs, log := credQueryRoundTrip(t,
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }, nil)
	if !resp.Success {
		t.Fatalf("expected success, got: %s / %s", resp.Error, resp.ErrorCode)
	}
	if obs.apiKey != credQuerySecret {
		t.Fatalf("server saw api_key = %q, want the injected secret", obs.apiKey)
	}
	if obs.headers.Get("Authorization") != "" {
		t.Fatalf("an empty header_template must send no Authorization header, got %q",
			obs.headers.Get("Authorization"))
	}
	assertNoSecretAnywhere(t, resp, log)
}

// TestCredentialHTTP_QueryTemplate_AppendsToExistingQuery — target_url 자체는
// 치환되지 않고 기존 query 바이트도 그대로 남는다.
func TestCredentialHTTP_QueryTemplate_AppendsToExistingQuery(t *testing.T) {
	resp, obs, _ := credQueryRoundTrip(t,
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") },
		func(req *proto.CredentialHTTPRequest) {
			req.TargetURL += "?scope=read"
			req.Policy.AllowQuery = true
		})
	if !resp.Success {
		t.Fatalf("expected success, got: %s / %s", resp.Error, resp.ErrorCode)
	}
	if !strings.HasPrefix(obs.rawQuery, "scope=read&") {
		t.Fatalf("existing query was rewritten: %q", obs.rawQuery)
	}
	if obs.apiKey != credQuerySecret {
		t.Fatalf("server saw api_key = %q, want the injected secret", obs.apiKey)
	}
}

// TestCredentialHTTP_QueryTemplate_NameCollisionRejected — 같은 이름을 caller 가
// 이미 넣었으면 거부한다. 어느 쪽을 서버가 읽을지는 Keeper 가 정할 수 없다.
func TestCredentialHTTP_QueryTemplate_NameCollisionRejected(t *testing.T) {
	reached := false
	resp, _, log := credQueryRoundTrip(t,
		func(w http.ResponseWriter, r *http.Request) { reached = true },
		func(req *proto.CredentialHTTPRequest) {
			req.TargetURL += "?api_key=agent-supplied"
			req.Policy.AllowQuery = true
		})
	if resp.Success {
		t.Fatal("a parameter name already present in target_url must fail closed")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
	if reached {
		t.Fatal("the request went out despite the collision")
	}
	assertNoSecretAnywhere(t, resp, log)
}

// TestCredentialHTTP_QueryTemplate_MismatchWithSignedPolicyRejected — 요청의
// query_template 이 서명된 것과 다르면 아무 바이트도 나가지 않는다.
func TestCredentialHTTP_QueryTemplate_MismatchWithSignedPolicyRejected(t *testing.T) {
	cases := map[string]func(*proto.CredentialHTTPRequest){
		"이름이 다르다": func(req *proto.CredentialHTTPRequest) {
			req.QueryTemplate = map[string]string{"apikey": "{{secret.token}}"}
		},
		"값이 다르다": func(req *proto.CredentialHTTPRequest) {
			req.QueryTemplate = map[string]string{"api_key": "x{{secret.token}}"}
		},
		"자리를 하나 더 넣었다": func(req *proto.CredentialHTTPRequest) {
			req.QueryTemplate["extra"] = "{{secret.token}}"
		},
		"서명에는 있는데 요청에서 뺐다": func(req *proto.CredentialHTTPRequest) {
			// header 쪽은 일치시켜 둔다 — 그러지 않으면 header 검사가 먼저
			// 걸려서 query 검사를 통과했는지 알 수 없다.
			req.HeaderTemplate = map[string]string{"X-K": "{{secret.token}}"}
			req.Policy.HeaderTemplate = map[string]string{"X-K": "{{secret.token}}"}
			req.QueryTemplate = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			reached := false
			resp, _, _ := credQueryRoundTrip(t,
				func(w http.ResponseWriter, r *http.Request) { reached = true }, mutate)
			if resp.Success {
				t.Fatal("query_template mismatch must fail closed")
			}
			if resp.Error != "query_template does not match signed credential policy" {
				t.Fatalf("error = %q, want the query_template mismatch rejection", resp.Error)
			}
			if reached {
				t.Fatal("the request went out despite the mismatch")
			}
		})
	}
}

// TestCredentialHTTP_QueryTemplate_EchoedSecretIsMasked — 계획 §5.2-4. 이 단계가
// 빠지면 query 로 넣은 비밀만 마스킹 사각지대가 된다.
func TestCredentialHTTP_QueryTemplate_EchoedSecretIsMasked(t *testing.T) {
	resp, _, log := credQueryRoundTrip(t,
		func(w http.ResponseWriter, r *http.Request) {
			// 대상 서버가 요청 URL 을 그대로 되비추는 흔한 모양. body 에는 퍼센트
			// 인코딩된 형태가, header 에는 디코드된 원문이 실린다.
			w.Header().Set("X-Echo-Key", r.URL.Query().Get("api_key"))
			w.WriteHeader(200)
			fmt.Fprintf(w, "requested %s?%s", r.URL.Path, r.URL.RawQuery)
		}, nil)
	if !resp.Success {
		t.Fatalf("expected success, got: %s / %s", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.CredentialHTTPResponseData)
	if !ok {
		t.Fatalf("response data type = %T", resp.Data)
	}
	body, err := base64.StdEncoding.DecodeString(data.BodyB64)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !strings.Contains(string(body), redactionMask) {
		t.Fatalf("expected the redaction mask in the body, got: %s", body)
	}
	if data.Headers["X-Echo-Key"] != redactionMask {
		t.Fatalf("echoed header = %q, want the mask", data.Headers["X-Echo-Key"])
	}
	assertNoSecretAnywhere(t, resp, log)
}

// TestCredentialHTTP_QueryTemplate_TransportErrorCarriesNoURL — 전송 실패는
// *url.Error 로 오고 그 메시지에는 주입된 URL 이 통째로 박혀 있다. 그대로
// 돌려주면 비밀이 IPC 로 나간다.
func TestCredentialHTTP_QueryTemplate_TransportErrorCarriesNoURL(t *testing.T) {
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true
	t.Cleanup(func() { testAllowLoopbackDial = prevLoopback })

	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"`+credQuerySecret+`"}}`, credTestAAD)

	policy := credTestPolicy([]string{"127.0.0.1"}, []string{"GET"})
	policy.HeaderTemplate = map[string]string{}
	policy.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}

	// 아무도 듣지 않는 포트 — client.Do 가 dial 단계에서 실패한다.
	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "https://127.0.0.1:1/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{},
		QueryTemplate:  map[string]string{"api_key": "{{secret.token}}"},
		Policy:         policy,
	})
	if resp.Success {
		t.Fatal("expected the dial to fail")
	}
	if resp.ErrorCode != string(errs.ErrCodeInternal) {
		t.Fatalf("error_code = %q, want internal_error", resp.ErrorCode)
	}
	assertNoSecretAnywhere(t, resp, log)
}

func TestInjectSecretQuery_FailClosed(t *testing.T) {
	secret := map[string]string{"token": "T0K3N", "bad": "line1\nline2"}
	cases := []struct {
		name     string
		target   string
		template map[string]string
	}{
		{"이름 충돌", "https://api.example/v1?api_key=agent", map[string]string{"api_key": "{{secret.token}}"}},
		{"빈 이름", "https://api.example/v1", map[string]string{"": "{{secret.token}}"}},
		{"이름에 제어문자", "https://api.example/v1", map[string]string{"a\rb": "{{secret.token}}"}},
		{"값에 CRLF", "https://api.example/v1", map[string]string{"api_key": "{{secret.bad}}"}},
		{"모르는 비밀 키", "https://api.example/v1", map[string]string{"api_key": "{{secret.missing}}"}},
		{"파싱 불가 query", "https://api.example/v1?%zz", map[string]string{"api_key": "{{secret.token}}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, injected, err := injectSecretQuery(tc.target, tc.template, secret, nil)
			if err == nil {
				t.Fatalf("expected an error, got url=%q injected=%v", got, injected)
			}
			if got != "" {
				t.Fatalf("a failed injection must return no URL, got %q", got)
			}
			if strings.Contains(err.Error(), "T0K3N") || strings.Contains(err.Error(), "line1") {
				t.Fatalf("error message leaked a secret value: %v", err)
			}
		})
	}
}

func TestInjectSecretQuery_EmptyTemplateIsAPassThrough(t *testing.T) {
	running := []string{"already-injected"}
	got, injected, err := injectSecretQuery("https://api.example/v1?a=1", nil,
		map[string]string{"token": "T0K3N"}, running)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "https://api.example/v1?a=1" {
		t.Fatalf("url = %q, want it untouched", got)
	}
	if len(injected) != 1 || injected[0] != "already-injected" {
		t.Fatalf("injected = %v, want the running list unchanged", injected)
	}
}

// TestInjectSecretQuery_MergesInjectedSecrets — 헤더로 이미 들어간 비밀과 query
// 로 들어간 비밀이 한 목록으로 합쳐져야 둘 다 마스킹된다.
func TestInjectSecretQuery_MergesInjectedSecrets(t *testing.T) {
	got, injected, err := injectSecretQuery("https://api.example/v1",
		map[string]string{"api_key": "{{secret.token}}", "sig": "{{secret.sig}}"},
		map[string]string{"token": "T0K3N", "sig": "LONGER-SIGNATURE"},
		[]string{"HEADER-SECRET"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "https://api.example/v1?api_key=T0K3N&sig=LONGER-SIGNATURE" {
		t.Fatalf("url = %q", got)
	}
	if len(injected) != 3 {
		t.Fatalf("injected = %v, want header + both query secrets", injected)
	}
	// 긴 것부터 — 다른 비밀의 부분 문자열인 비밀이 나중에 마스킹된다.
	if len(injected[0]) < len(injected[1]) || len(injected[1]) < len(injected[2]) {
		t.Fatalf("injected is not longest-first: %v", injected)
	}
}

// TestCredentialHTTPRequest_ValidateTemplates — 둘 중 하나만 있어도 통과하고
// 둘 다 비면 거부한다.
func TestCredentialHTTPRequest_ValidateTemplates(t *testing.T) {
	base := func() proto.CredentialHTTPRequest {
		return proto.CredentialHTTPRequest{
			GroupHandle:    strings.Repeat("A", 32),
			IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
			CiphertextB64:  base64.StdEncoding.EncodeToString([]byte("ciphertext")),
			AADB64:         base64.StdEncoding.EncodeToString([]byte(credTestAAD)),
			TargetURL:      "https://api.example/x",
			Method:         "GET",
			HeaderTemplate: map[string]string{},
			Policy:         credTestPolicy([]string{"api.example"}, []string{"GET"}),
		}
	}

	queryOnly := base()
	queryOnly.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}
	queryOnly.Policy.HeaderTemplate = map[string]string{}
	queryOnly.Policy.QueryTemplate = map[string]string{"api_key": "{{secret.token}}"}
	if err := queryOnly.Validate(); err != nil {
		t.Fatalf("query_template 만 있는 요청은 통과해야 한다: %v", err)
	}

	neither := base()
	neither.Policy.HeaderTemplate = map[string]string{}
	if err := neither.Validate(); err == nil {
		t.Fatal("두 template 이 모두 비면 거부해야 한다")
	}
}
