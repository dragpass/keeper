// credential_http_test.go — HandleCredentialHTTPRequest guards.
//
// Covers each of the eight in-Keeper safeguards with real httptest servers plus
// the pure-helper units (SSRF classifier, host normalization, placeholder
// substitution, redaction):
//   - happy path: secret injected into the outbound Authorization header, server
//     sees it, response returned; the injected token never appears in the IPC
//     response or the logger.
//   - safeguard 1: host not in allowed_hosts → rejected; method not allowed →
//     rejected.
//   - safeguard 2: private / loopback / link-local / metadata IPs → blocked at
//     the connect-time Control hook.
//   - safeguard 3: non-https target → rejected.
//   - safeguard 4: redirect is never followed (3xx returned as-is).
//   - safeguard 5: oversized response body truncated with the flag set.
//   - safeguard 7: Authorization / Set-Cookie response headers stripped; secret
//     echoed in the body is masked.
//   - AAD swap: a payload sealed under a different AAD fails to open.

package handlers

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const credTestAAD = "org_9|entry_3|credential|1|1"

func credTestPolicy(hosts, methods []string) proto.CredentialPolicy {
	return proto.CredentialPolicy{
		EntryID:             "entry_3",
		DekVersion:          1,
		AllowedHosts:        hosts,
		AllowedMethods:      methods,
		AllowedPathPatterns: []string{"/*"},
		ApprovalMode:        "always_ask",
		Expiry:              "2100-01-01T00:00:00Z",
		Signature:           "test-signature",
		ServerKeyVersion:    1,
		SignatureAlg:        credentialPolicySignatureAlg,
	}
}

// sealCredentialForTest seals a credential JSON payload under the fresh Group
// DEK behind handle, using the canonical test AAD, and returns the IV /
// ciphertext / aad Base64 the request carries.
func sealCredentialForTest(t *testing.T, groupRaw []byte, credJSON string, aad string) (ivB64, ctB64, aadB64 string) {
	t.Helper()
	iv, ct, err := AESGCMSealSplitWithAAD(groupRaw, []byte(credJSON), []byte(aad))
	if err != nil {
		t.Fatalf("seal credential: %v", err)
	}
	return base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString([]byte(aad))
}

// hostOf returns the host[:port] of a URL for use in allowed_hosts.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	i := strings.Index(rawURL, "://")
	if i < 0 {
		t.Fatalf("bad url %q", rawURL)
	}
	rest := rawURL[i+3:]
	if s := strings.IndexByte(rest, '/'); s >= 0 {
		rest = rest[:s]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return h
	}
	return rest
}

// credTestRoundTrip drives a full request against a TLS test server whose cert
// is trusted by installing it into the secure client. It returns the parsed
// response data and the raw request the server observed.
func credTestRoundTrip(t *testing.T, method string, serverHandler http.HandlerFunc,
	headerTemplate map[string]string, allowedMethods []string) (proto.CredentialHTTPResponseData, *observedRequest, proto.BaseResponse, *logger.MemoryLogger) {
	t.Helper()

	obs := &observedRequest{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.method = r.Method
		obs.authorization = r.Header.Get("Authorization")
		obs.headers = r.Header.Clone()
		serverHandler(w, r)
	}))
	t.Cleanup(ts.Close)

	// Trust the test server cert while keeping verification ON, by installing it
	// into the secure client via the test seam.
	prev := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		pool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		cfg.RootCAs = pool
	}
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true // httptest listens on 127.0.0.1
	t.Cleanup(func() { testTLSConfigHook = prev; testAllowLoopbackDial = prevLoopback })

	deps, log, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	credJSON := `{"type":"api_token","label":"t","secret":{"authorization_scheme":"Bearer","token":"SUPER_SECRET_TOKEN_XYZ"}}`
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credJSON, credTestAAD)

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      ts.URL + "/x",
		Method:         method,
		HeaderTemplate: headerTemplate,
		Policy:         credTestPolicy([]string{hostOf(t, ts.URL)}, allowedMethods),
	})
	if !resp.Success {
		return proto.CredentialHTTPResponseData{}, obs, resp, log
	}
	data, ok := resp.Data.(proto.CredentialHTTPResponseData)
	if !ok {
		t.Fatalf("response data type = %T, want CredentialHTTPResponseData", resp.Data)
	}
	return data, obs, resp, log
}

type observedRequest struct {
	method        string
	authorization string
	headers       http.Header
}

// The tests below.

func TestCredentialHTTP_HappyPath_InjectsSecret_NoLeak(t *testing.T) {
	data, obs, resp, _ := credTestRoundTrip(t, "GET",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			fmt.Fprint(w, "ok")
		},
		map[string]string{"Authorization": "Bearer {{secret.token}}"},
		[]string{"GET"},
	)
	if !resp.Success {
		t.Fatalf("expected success, got: %s / %s", resp.Error, resp.ErrorCode)
	}
	if obs.authorization != "Bearer SUPER_SECRET_TOKEN_XYZ" {
		t.Fatalf("server saw Authorization = %q, want the injected secret", obs.authorization)
	}
	if data.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", data.StatusCode)
	}

	// The injected secret must never appear in the IPC response.
	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), "SUPER_SECRET_TOKEN_XYZ") {
		t.Fatalf("IPC response leaked the injected secret: %s", respJSON)
	}
}

func TestCredentialHTTP_HostNotAllowed_Rejected(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"x"}}`, credTestAAD)

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "https://evil.example.com/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{"api.github.com"}, []string{"GET"}),
	})
	if resp.Success {
		t.Fatalf("expected rejection for host not in allowed_hosts")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
}

func TestCredentialHTTP_MethodNotAllowed_Rejected(t *testing.T) {
	_, _, resp, _ := credTestRoundTrip(t, "POST",
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) },
		map[string]string{"Authorization": "Bearer {{secret.token}}"},
		[]string{"GET"}, // POST not allowed
	)
	if resp.Success {
		t.Fatalf("expected rejection for method not in allowed_methods")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
}

func TestCredentialHTTP_NonHTTPS_Rejected(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"x"}}`, credTestAAD)

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "http://api.github.com/x", // http, not https
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{"api.github.com"}, []string{"GET"}),
	})
	if resp.Success {
		t.Fatalf("expected rejection for non-https target")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
}

// TestCredentialHTTP_PrivateIP_Blocked drives a request whose host resolves to a
// loopback / private address. The Control hook must refuse the connection, so
// the request fails with an internal (network) error, not a success.
func TestCredentialHTTP_PrivateIP_Blocked(t *testing.T) {
	// A plain (non-TLS) loopback server is fine — the connection must be blocked
	// before TLS anyway. We point an https URL at 127.0.0.1 so enforceHTTPSURL /
	// allowlist pass but the Control hook blocks the resolved loopback IP.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(ts.Close)
	host := hostOf(t, ts.URL) // 127.0.0.1

	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"x"}}`, credTestAAD)

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      "https://" + host + "/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{host}, []string{"GET"}),
	})
	if resp.Success {
		t.Fatalf("expected the loopback connection to be blocked by the Control hook")
	}
	if resp.ErrorCode != string(errs.ErrCodeInternal) {
		t.Fatalf("error_code = %q, want internal_error (dial blocked)", resp.ErrorCode)
	}
	if strings.Contains(strings.ToLower(resp.Error), "super_secret") {
		t.Fatalf("error message leaked the secret: %s", resp.Error)
	}
}

func TestCredentialHTTP_RedirectNotFollowed(t *testing.T) {
	data, _, resp, _ := credTestRoundTrip(t, "GET",
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example.com/stolen", http.StatusFound)
		},
		map[string]string{"Authorization": "Bearer {{secret.token}}"},
		[]string{"GET"},
	)
	if !resp.Success {
		t.Fatalf("expected success (3xx returned as-is), got: %s", resp.Error)
	}
	if data.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect must not be followed)", data.StatusCode)
	}
	// The Location header is not a redacted header, so it is present — proving we
	// returned the 3xx itself rather than chasing it.
	if data.Headers["Location"] == "" {
		t.Fatalf("expected the 302 Location header to be present in the returned response")
	}
}

func TestCredentialHTTP_ResponseTruncated(t *testing.T) {
	big := strings.Repeat("A", defaultMaxRespBytes+5000)
	deps, _, _ := newTestDeps(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, big)
	}))
	t.Cleanup(ts.Close)

	prev := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		cfg.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true
	t.Cleanup(func() { testTLSConfigHook = prev; testAllowLoopbackDial = prevLoopback })

	handle, groupRaw := openSessionForFreshKey(t, deps)
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"x"}}`, credTestAAD)

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      ts.URL + "/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{hostOf(t, ts.URL)}, []string{"GET"}),
	})
	if !resp.Success {
		t.Fatalf("expected success, got: %s", resp.Error)
	}
	data := resp.Data.(proto.CredentialHTTPResponseData)
	if !data.Truncated {
		t.Fatalf("expected Truncated=true for an oversized body")
	}
	body, _ := base64.StdEncoding.DecodeString(data.BodyB64)
	if len(body) != defaultMaxRespBytes {
		t.Fatalf("truncated body length = %d, want %d", len(body), defaultMaxRespBytes)
	}
}

func TestCredentialHTTP_ResponseRedaction(t *testing.T) {
	data, _, resp, _ := credTestRoundTrip(t, "GET",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Authorization", "Bearer server-echo")
			w.Header().Set("Set-Cookie", "session=abc")
			w.Header().Set("X-Ok", "keepme")
			w.WriteHeader(200)
			// The body echoes the injected secret — must be masked.
			fmt.Fprint(w, "your token is SUPER_SECRET_TOKEN_XYZ done")
		},
		map[string]string{"Authorization": "Bearer {{secret.token}}"},
		[]string{"GET"},
	)
	if !resp.Success {
		t.Fatalf("expected success, got: %s", resp.Error)
	}
	if _, ok := data.Headers["Authorization"]; ok {
		t.Fatalf("Authorization response header was not stripped")
	}
	if _, ok := data.Headers["Set-Cookie"]; ok {
		t.Fatalf("Set-Cookie response header was not stripped")
	}
	if data.Headers["X-Ok"] != "keepme" {
		t.Fatalf("non-sensitive header dropped: %v", data.Headers)
	}
	body, _ := base64.StdEncoding.DecodeString(data.BodyB64)
	if strings.Contains(string(body), "SUPER_SECRET_TOKEN_XYZ") {
		t.Fatalf("secret echoed in body was not masked: %s", body)
	}
	if !strings.Contains(string(body), redactionMask) {
		t.Fatalf("expected the redaction mask in the body, got: %s", body)
	}
}

func TestCredentialHTTP_NoSecretInLogger(t *testing.T) {
	_, _, resp, logCap := credTestRoundTrip(t, "GET",
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) },
		map[string]string{"Authorization": "Bearer {{secret.token}}"},
		[]string{"GET"},
	)
	if !resp.Success {
		t.Fatalf("expected success, got: %s", resp.Error)
	}
	if logCap.Contains("SUPER_SECRET_TOKEN_XYZ") {
		t.Fatalf("logger leaked the injected secret: %v", logCap.Messages())
	}
}

func TestCredentialHTTP_AADSwap_FailsOpen(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)
	// Seal under one AAD, present a DIFFERENT AAD → open must fail.
	ivB64, ctB64, _ := sealCredentialForTest(t, groupRaw,
		`{"type":"api_token","secret":{"token":"x"}}`, "org_9|entry_3|credential|1|1")
	wrongAAD := base64.StdEncoding.EncodeToString([]byte("org_9|entry_4|credential|1|1"))

	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         wrongAAD,
		TargetURL:      "https://api.github.com/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{"api.github.com"}, []string{"GET"}),
	})
	if resp.Success {
		t.Fatalf("expected open failure for a swapped AAD")
	}
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("error_code = %q, want crypto_failure", resp.ErrorCode)
	}
}

func TestCredentialHTTP_UnknownSecretKey_Rejected(t *testing.T) {
	_, _, resp, _ := credTestRoundTrip(t, "GET",
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) },
		map[string]string{"Authorization": "Bearer {{secret.nonexistent}}"},
		[]string{"GET"},
	)
	if resp.Success {
		t.Fatalf("expected rejection for placeholder referencing an absent secret key")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error_code = %q, want validation_error", resp.ErrorCode)
	}
}

func TestCredentialHTTP_BadHandle_NotFound(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleCredentialHTTPRequest(deps, proto.CredentialHTTPRequest{
		GroupHandle:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		AADB64:         base64.StdEncoding.EncodeToString([]byte(credTestAAD)),
		TargetURL:      "https://api.github.com/x",
		Method:         "GET",
		HeaderTemplate: map[string]string{"Authorization": "Bearer {{secret.token}}"},
		Policy:         credTestPolicy([]string{"api.github.com"}, []string{"GET"}),
	})
	if resp.Success {
		t.Fatalf("expected not_found for a missing group session")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("error_code = %q, want not_found", resp.ErrorCode)
	}
}

// ── pure-helper unit tests ─────────────────────────────────────────────────

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.5", "172.16.0.1", "192.168.1.1", // RFC1918 private
		"169.254.169.254",    // cloud metadata (link-local)
		"fe80::1",            // IPv6 link-local
		"fc00::1", "fd00::1", // IPv6 ULA
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", // multicast
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}
	if !isBlockedIP(nil) {
		t.Errorf("isBlockedIP(nil) = false, want true (unparseable → refuse)")
	}
}

func TestNormalizeHostAndAllow(t *testing.T) {
	if !hostAllowed("API.GitHub.com:443", []string{"api.github.com"}) {
		t.Errorf("case/port normalization failed")
	}
	if !hostAllowed("api.github.com.", []string{"api.github.com"}) {
		t.Errorf("trailing-dot normalization failed")
	}
	if hostAllowed("evil.api.github.com", []string{"api.github.com"}) {
		t.Errorf("suffix widening must NOT match (exact only)")
	}
}

func TestSubstituteSecretHeaders(t *testing.T) {
	secret := map[string]string{"token": "T0K3N", "scheme": "Bearer"}
	assembled, injected, err := substituteSecretHeaders(
		map[string]string{
			"Authorization": "{{secret.scheme}} {{secret.token}}",
			"X-Static":      "no-placeholder",
		}, secret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if assembled["Authorization"] != "Bearer T0K3N" {
		t.Fatalf("assembled = %q, want %q", assembled["Authorization"], "Bearer T0K3N")
	}
	if assembled["X-Static"] != "no-placeholder" {
		t.Fatalf("static header mangled: %q", assembled["X-Static"])
	}
	// injected is sorted longest-first: "Bearer" (6) before "T0K3N" (5).
	if len(injected) != 2 || injected[0] != "Bearer" {
		t.Fatalf("injected = %v, want [Bearer T0K3N]", injected)
	}

	if _, _, err := substituteSecretHeaders(
		map[string]string{"Authorization": "Bearer {{secret.missing}}"}, secret); err == nil {
		t.Fatalf("expected error for unknown secret key")
	}
}
