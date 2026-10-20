// credential_single_use_test.go — one signed credential policy, at most one
// execution attempt, and the query and body it carries are the ones signed.
//
// Every test drives HandleCredentialHTTPRequest against a TLS test server and
// counts what reached it, because the property is about the target: a refused
// request must not have been sent.

package handlers

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// singleUseServer is a TLS test server trusted by the secure client. hits
// counts requests that reached the handler; lastQuery and lastBody hold what
// the last one carried.
type singleUseServer struct {
	url       string
	hits      atomic.Int32
	mu        sync.Mutex
	lastQuery string
	lastBody  string
}

func newSingleUseServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *singleUseServer {
	t.Helper()
	s := &singleUseServer{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		body := make([]byte, 1<<16)
		n, _ := r.Body.Read(body)
		s.mu.Lock()
		s.lastQuery = r.URL.RawQuery
		s.lastBody = string(body[:n])
		s.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	prev := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		cfg.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true
	t.Cleanup(func() { testTLSConfigHook = prev; testAllowLoopbackDial = prevLoopback })
	s.url = ts.URL
	return s
}

// mintCredentialNonce runs the real prepare action against deps.
func mintCredentialNonce(t *testing.T, deps Deps) string {
	t.Helper()
	resp := HandleCredentialExecutionPrepare(deps, proto.CredentialExecutionPrepareRequest{})
	if !resp.Success {
		t.Fatalf("prepare failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.CredentialExecutionPrepareResponseData)
	if !ok {
		t.Fatalf("prepare data type = %T", resp.Data)
	}
	return data.ExecutionNonce
}

func bodyDigestHex(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// singleUseRequest builds a well-formed POST to server s whose policy is
// version 2, signs query and body exactly, and names nonce.
func singleUseRequest(t *testing.T, deps Deps, s *singleUseServer, query string, body []byte, nonce string) proto.CredentialHTTPRequest {
	t.Helper()
	handle, groupRaw := openSessionForFreshKey(t, deps)
	credJSON := `{"type":"api_token","label":"t","secret":{"token":"SUPER_SECRET_TOKEN_XYZ"}}`
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credJSON, credTestAAD)
	policy := credTestPolicy([]string{hostOf(t, s.url)}, []string{"POST"})
	policy.AllowQuery = true
	policy.AllowBody = true
	policy.PolicyVersion = proto.CredentialPolicyVersion
	policy.ExecutionNonce = nonce
	policy.TargetQuery = query
	policy.BodySHA256 = bodyDigestHex(body)
	target := s.url + "/x"
	if query != "" {
		target += "?" + query
	}
	req := proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      target,
		Method:         "POST",
		HeaderTemplate: policy.HeaderTemplate,
		Policy:         policy,
	}
	if len(body) > 0 {
		req.BodyB64 = base64.StdEncoding.EncodeToString(body)
	}
	return req
}

func requireRefused(t *testing.T, resp proto.BaseResponse, code errs.ErrorCode) {
	t.Helper()
	if resp.Success {
		t.Fatalf("request succeeded, want refusal %s", code)
	}
	if resp.ErrorCode != string(code) {
		t.Fatalf("error_code = %q (%s), want %q", resp.ErrorCode, resp.Error, code)
	}
}

func TestCredentialHTTP_SameSignedPolicyTwice_SecondRefused(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))

	if first := HandleCredentialHTTPRequest(deps, req); !first.Success {
		t.Fatalf("first submission failed: %s (%s)", first.Error, first.ErrorCode)
	}
	second := HandleCredentialHTTPRequest(deps, req)
	requireRefused(t, second, errs.ErrCodeCredentialNonceInvalid)
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("target saw %d requests, want 1", got)
	}
}

// Eight submissions of one signed policy released together through a barrier:
// exactly one reaches the target.
func TestCredentialHTTP_ConcurrentSubmissionsOfOnePolicy_ExactlyOneRuns(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))

	const n = 8
	barrier := make(chan struct{})
	var ready, done sync.WaitGroup
	var succeeded atomic.Int32
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-barrier
			if HandleCredentialHTTPRequest(deps, req).Success {
				succeeded.Add(1)
			}
		}()
	}
	ready.Wait()
	close(barrier)
	done.Wait()

	if got := succeeded.Load(); got != 1 {
		t.Fatalf("%d submissions succeeded, want 1", got)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("target saw %d requests, want 1", got)
	}
}

// A Keeper serving from another nonce map (another device or OS user, a
// standalone process) or a restarted owner has no entry for the nonce. This
// simulates both with a separate store and a nil store in one process; it does
// not run a second process, a proxy, or a real restart.
func TestCredentialHTTP_NonceFromAnotherNonceMapRefused(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))

	other := deps
	other.CredentialNonces = NewCredentialNonceStore()
	requireRefused(t, HandleCredentialHTTPRequest(other, req), errs.ErrCodeCredentialNonceInvalid)

	restarted := deps
	restarted.CredentialNonces = nil
	requireRefused(t, HandleCredentialHTTPRequest(restarted, req), errs.ErrCodeCredentialNonceInvalid)

	if got := s.hits.Load(); got != 0 {
		t.Fatalf("target saw %d requests, want 0", got)
	}
}

func TestCredentialHTTP_ExpiredNonceRefused(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	deps.Clock = func() time.Time { return now }
	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
	now = now.Add(credentialNonceTTL)
	requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeCredentialNonceInvalid)
	if got := s.hits.Load(); got != 0 {
		t.Fatalf("target saw %d requests, want 0", got)
	}
}

func TestCredentialHTTP_PolicyWithoutNonceRefused(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	mintCredentialNonce(t, deps)
	req := singleUseRequest(t, deps, s, "", nil, "")
	if resp := HandleCredentialHTTPRequest(deps, req); resp.Success {
		t.Fatal("a policy without an execution nonce was accepted")
	}
	if got := s.hits.Load(); got != 0 {
		t.Fatalf("target saw %d requests, want 0", got)
	}
}

// The format that bound neither nonce, query nor body is refused outright,
// before the signature is checked. The test verifier accepts every signature,
// so only the version check can refuse these.
func TestCredentialHTTP_LegacyPolicyVersionRefused(t *testing.T) {
	for _, version := range []int{0, 1, 3} {
		s := newSingleUseServer(t, nil)
		deps, _, _ := newTestDeps(t)
		req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
		req.Policy.PolicyVersion = version
		requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
		if got := s.hits.Load(); got != 0 {
			t.Fatalf("version %d: target saw %d requests, want 0", version, got)
		}
	}
}

func TestCredentialHTTP_QueryMustEqualSignedBytes(t *testing.T) {
	const signed = "a=1&b=2&b=3&q=x%20y"
	tampered := map[string]string{
		"reordered":           "b=2&a=1&b=3&q=x%20y",
		"duplicate added":     "a=1&a=1&b=2&b=3&q=x%20y",
		"duplicate removed":   "a=1&b=2&q=x%20y",
		"encoding changed":    "a=%31&b=2&b=3&q=x%20y",
		"plus for space":      "a=1&b=2&b=3&q=x+y",
		"lowercase escape":    "a=1&b=2&b=3&q=x%2fy",
		"parameter added":     signed + "&c=4",
		"query dropped":       "",
		"trailing ampersand":  signed + "&",
		"value changed":       "a=1&b=2&b=3&q=x%20z",
		"leading empty field": "&" + signed,
	}
	for name, sent := range tampered {
		t.Run(name, func(t *testing.T) {
			s := newSingleUseServer(t, nil)
			deps, _, _ := newTestDeps(t)
			req := singleUseRequest(t, deps, s, signed, nil, mintCredentialNonce(t, deps))
			req.TargetURL = s.url + "/x"
			if sent != "" {
				req.TargetURL += "?" + sent
			}
			requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
			if got := s.hits.Load(); got != 0 {
				t.Fatalf("target saw %d requests, want 0", got)
			}
		})
	}

	t.Run("exact bytes are sent as signed", func(t *testing.T) {
		s := newSingleUseServer(t, nil)
		deps, _, _ := newTestDeps(t)
		req := singleUseRequest(t, deps, s, signed, nil, mintCredentialNonce(t, deps))
		if resp := HandleCredentialHTTPRequest(deps, req); !resp.Success {
			t.Fatalf("exact query refused: %s (%s)", resp.Error, resp.ErrorCode)
		}
		if s.lastQuery != signed {
			t.Fatalf("target saw query %q, want %q", s.lastQuery, signed)
		}
	})
}

func TestCredentialHTTP_TargetURLShapesThatHideTheQueryAreRefused(t *testing.T) {
	for name, suffix := range map[string]string{
		"fragment":               "?a=1#frag",
		"empty question mark":    "?",
		"space in query":         "?a=1 2",
		"non-ascii in query":     "?a=é",
		"fragment without query": "#frag",
	} {
		t.Run(name, func(t *testing.T) {
			s := newSingleUseServer(t, nil)
			deps, _, _ := newTestDeps(t)
			req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
			req.TargetURL = s.url + "/x" + suffix
			req.Policy.TargetQuery = strings.TrimPrefix(strings.SplitN(suffix, "#", 2)[0], "?")
			requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
			if got := s.hits.Load(); got != 0 {
				t.Fatalf("target saw %d requests, want 0", got)
			}
		})
	}
}

func TestCredentialHTTP_BodyMustMatchSignedDigest(t *testing.T) {
	signed := []byte(`{"amount":100}`)
	for name, sent := range map[string][]byte{
		"one byte changed": []byte(`{"amount":900}`),
		"appended":         append(append([]byte(nil), signed...), ' '),
		"body dropped":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			s := newSingleUseServer(t, nil)
			deps, _, _ := newTestDeps(t)
			req := singleUseRequest(t, deps, s, "", signed, mintCredentialNonce(t, deps))
			req.BodyB64 = ""
			if len(sent) > 0 {
				req.BodyB64 = base64.StdEncoding.EncodeToString(sent)
			}
			requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
			if got := s.hits.Load(); got != 0 {
				t.Fatalf("target saw %d requests, want 0", got)
			}
		})
	}

	t.Run("body added to a policy that signed none", func(t *testing.T) {
		s := newSingleUseServer(t, nil)
		deps, _, _ := newTestDeps(t)
		req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
		req.BodyB64 = base64.StdEncoding.EncodeToString(signed)
		requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
		if got := s.hits.Load(); got != 0 {
			t.Fatalf("target saw %d requests, want 0", got)
		}
	})

	t.Run("exact bytes are sent", func(t *testing.T) {
		s := newSingleUseServer(t, nil)
		deps, _, _ := newTestDeps(t)
		req := singleUseRequest(t, deps, s, "", signed, mintCredentialNonce(t, deps))
		if resp := HandleCredentialHTTPRequest(deps, req); !resp.Success {
			t.Fatalf("exact body refused: %s (%s)", resp.Error, resp.ErrorCode)
		}
		if s.lastBody != string(signed) {
			t.Fatalf("target saw body %q, want %q", s.lastBody, signed)
		}
	})
}

// A refused binding check must not spend the nonce: the request never left,
// so the same policy with the signed request still runs once.
func TestCredentialHTTP_MismatchDoesNotSpendTheNonce(t *testing.T) {
	s := newSingleUseServer(t, nil)
	deps, _, _ := newTestDeps(t)
	req := singleUseRequest(t, deps, s, "a=1", nil, mintCredentialNonce(t, deps))
	bad := req
	bad.TargetURL = s.url + "/x?a=2"
	requireRefused(t, HandleCredentialHTTPRequest(deps, bad), errs.ErrCodeValidation)
	if resp := HandleCredentialHTTPRequest(deps, req); !resp.Success {
		t.Fatalf("signed request refused after a mismatch: %s (%s)", resp.Error, resp.ErrorCode)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("target saw %d requests, want 1", got)
	}
}

// The target receives the request and the connection drops before a response.
// Keeper cannot know whether the target acted, says so, and does not retry.
func TestCredentialHTTP_ConnectionLostAfterSend_IsOutcomeUnknown(t *testing.T) {
	s := newSingleUseServer(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})
	deps, _, _ := newTestDeps(t)
	// HTTP/1.1 so the handler can hijack and drop the connection mid-request.
	prevHook := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		prevHook(cfg)
		cfg.NextProtos = []string{"http/1.1"}
	}
	t.Cleanup(func() { testTLSConfigHook = prevHook })

	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
	resp := HandleCredentialHTTPRequest(deps, req)
	requireRefused(t, resp, errs.ErrCodeCredentialOutcomeUnknown)
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("target saw %d requests, want exactly 1 (no retry)", got)
	}
	requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeCredentialNonceInvalid)
}

// A failure before any byte is written is not an unknown outcome: the request
// certainly did not reach the target.
func TestCredentialHTTP_RefusedBeforeSend_IsNotOutcomeUnknown(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	credJSON := `{"type":"api_token","label":"t","secret":{"token":"SUPER_SECRET_TOKEN_XYZ"}}`
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credJSON, credTestAAD)
	policy := credTestPolicy([]string{"127.0.0.1:1"}, []string{"GET"})
	policy.PolicyVersion = proto.CredentialPolicyVersion
	policy.ExecutionNonce = mintCredentialNonce(t, deps)
	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "https://127.0.0.1:1/x",
		Method:         "GET",
		HeaderTemplate: policy.HeaderTemplate,
		Policy:         policy,
	})
	if resp.Success {
		t.Fatal("a loopback target was reached")
	}
	if resp.ErrorCode == string(errs.ErrCodeCredentialOutcomeUnknown) {
		t.Fatalf("a request blocked before connect reported an unknown outcome: %s", resp.Error)
	}
}

func TestCredentialExecutionPrepare_MintsDistinctNonces(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	a, b := mintCredentialNonce(t, deps), mintCredentialNonce(t, deps)
	if len(a) != proto.CredentialExecutionNonceChars || len(b) != proto.CredentialExecutionNonceChars {
		t.Fatalf("nonce lengths %d, %d, want %d", len(a), len(b), proto.CredentialExecutionNonceChars)
	}
	if a == b {
		t.Fatal("two prepares returned the same nonce")
	}
	if _, err := base64.RawURLEncoding.DecodeString(a); err != nil {
		t.Fatalf("nonce is not unpadded Base64URL: %v", err)
	}
}

func TestCredentialNonceStore_FullRefusesInsteadOfEvicting(t *testing.T) {
	store := NewCredentialNonceStore()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < credentialMaxNonces; i++ {
		if _, err := store.Put(strings.Repeat("n", 10)+string(rune('a'+i%26))+strings.Repeat("x", i), now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if _, err := store.Put("one-too-many", now); err == nil {
		t.Fatal("a full store accepted another nonce")
	}
	if !store.Consume(strings.Repeat("n", 10)+"a", now) {
		t.Fatal("the first nonce was evicted")
	}
}

// armCredentialPolicy makes p a version 2 policy that signs exactly what the
// request carries, with a nonce minted by deps: what a correct server returns
// for that request. Tests that are not about the binding go through it so they
// keep exercising what they were written for.
func armCredentialPolicy(t *testing.T, deps Deps, p proto.CredentialPolicy, targetURL string, body []byte) proto.CredentialPolicy {
	t.Helper()
	if p.PolicyVersion == 0 {
		p.PolicyVersion = proto.CredentialPolicyVersion
	}
	if p.ExecutionNonce == "" {
		p.ExecutionNonce = mintCredentialNonce(t, deps)
	}
	if p.TargetQuery == "" && targetURL != "" {
		if i := strings.IndexByte(targetURL, '?'); i >= 0 {
			p.TargetQuery = strings.SplitN(targetURL[i+1:], "#", 2)[0]
		}
	}
	if p.BodySHA256 == "" {
		p.BodySHA256 = bodyDigestHex(body)
	}
	return p
}

func handleArmedHTTP(t *testing.T, deps Deps, req proto.CredentialHTTPRequest) proto.BaseResponse {
	t.Helper()
	body, _ := base64.StdEncoding.DecodeString(req.BodyB64)
	req.Policy = armCredentialPolicy(t, deps, req.Policy, req.TargetURL, body)
	return HandleCredentialHTTPRequest(deps, req)
}

func handleArmedExec(t *testing.T, deps Deps, req proto.CredentialExecRequest) proto.BaseResponse {
	t.Helper()
	req.Policy = armCredentialPolicy(t, deps, req.Policy, "", nil)
	return HandleCredentialExecRequest(deps, req)
}
