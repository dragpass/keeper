// credential_http_safety.go — the security-critical pure helpers behind
// credential_http_request, isolated from the handler orchestration in
// credential_http.go so a security reviewer can read (and the tests can exercise)
// each safeguard on its own.
//
// Resident helpers:
//   - normalizeHost           — lowercase, strip port, strip trailing dot
//   - hostAllowed / methodAllowed — policy re-validation (safeguard 1)
//   - isBlockedIP             — SSRF private/loopback/link-local/ULA classifier (safeguard 2)
//   - newSecureHTTPClient     — TLS-only, redirect-blocked, connect-time IP re-check client (safeguards 2/3/4/6)
//   - enforceHTTPSURL         — https-only target parsing (safeguard 3)
//   - substituteSecretHeaders — {{secret.<key>}} placeholder resolution
//   - redactResponseHeaders / redactBody — response redaction (safeguard 7)

package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// secretPlaceholderRe matches {{secret.<key>}} with optional surrounding
// whitespace; <key> is limited to identifier characters.
var secretPlaceholderRe = regexp.MustCompile(`\{\{\s*secret\.([A-Za-z0-9_]+)\s*\}\}`)

// redactedHeaderNames are response headers stripped before returning to the
// caller. Canonicalized (http.Header form) for case-insensitive matching.
var redactedHeaderNames = map[string]bool{
	"Authorization":       true,
	"Set-Cookie":          true,
	"Proxy-Authorization": true,
}

const redactionMask = "***REDACTED***"

// testTLSConfigHook is a test-only seam. Production leaves it nil (no-op). Tests
// use it to trust an httptest server's self-signed certificate by installing its
// Cert pool as RootCAs, while keeping InsecureSkipVerify=false and TLS
// verification fully ON — so the HTTPS-only safeguard stays exercised end to end.
var testTLSConfigHook func(*tls.Config)

// testAllowLoopbackDial is a test-only seam. Production leaves it false, so the
// connect-time Control hook blocks loopback like any other non-public address.
// End-to-end tests set it true because httptest servers listen on 127.0.0.1;
// the dedicated SSRF test leaves it false to prove loopback is refused.
var testAllowLoopbackDial bool

// normalizeHost lowercases the host, drops any port, and strips a single
// trailing dot (the FQDN root label) so allowlist comparison is stable.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	// Strip port if present. SplitHostPort fails when there is no port, in
	// which case the original host is used as-is.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

// hostAllowed reports whether host exactly matches one of the policy's allowed
// hosts after normalization. There is no wildcard / suffix matching — exact
// match only, so a policy for api.github.com cannot be widened to
// evil.api.github.com.
func hostAllowed(host string, allowed []string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	for _, a := range allowed {
		if normalizeHost(a) == h {
			return true
		}
	}
	return false
}

// methodAllowed reports whether method (case-insensitive) is in the policy's
// allowlist.
func methodAllowed(method string, allowed []string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	for _, a := range allowed {
		if strings.ToUpper(strings.TrimSpace(a)) == m {
			return true
		}
	}
	return false
}

// pathAllowed matches the URL's escaped path against exact paths or a single
// trailing /* prefix pattern. Matching the escaped representation avoids path
// decoding ambiguities between policy evaluation and the outbound request.
func pathAllowed(target string, allowed []string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, pattern := range allowed {
		if pattern == path {
			return true
		}
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

func requestShapeAllowed(target string, hasBody, allowQuery, allowBody bool) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	return (allowQuery || u.RawQuery == "") && (allowBody || !hasBody)
}

func headerTemplatesEqual(actual, signed map[string]string) bool {
	if len(actual) != len(signed) {
		return false
	}
	for key, value := range signed {
		if actual[key] != value {
			return false
		}
	}
	return true
}

// isBlockedIP reports whether ip is a non-public destination the Keeper must
// refuse to connect to: RFC1918 private (10/8, 172.16/12, 192.168/16) and IPv6
// ULA (fc00::/7) via IsPrivate; loopback (127/8, ::1), link-local unicast
// (169.254/16 incl. the 169.254.169.254 cloud metadata endpoint, fe80::/10),
// multicast, and unspecified via !IsGlobalUnicast. IPv4-mapped IPv6 forms are
// handled by the stdlib classifiers (they consult To4()).
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true // unparseable → refuse
	}
	if ip.IsPrivate() {
		return true // 10/8, 172.16/12, 192.168/16, fc00::/7
	}
	// IsGlobalUnicast is false for loopback, link-local, multicast, and
	// unspecified addresses (but true for private, hence the explicit check
	// above). Refusing everything that is not global unicast covers the rest.
	return !ip.IsGlobalUnicast()
}

// newSecureHTTPClient builds the locked-down client used for the single
// outbound request:
//   - Dialer.Control re-checks the *resolved* IP at connect time, so a DNS name
//     that passed the host allowlist but resolves (or re-resolves, DNS
//     rebinding) to a private/metadata IP is refused before any bytes are sent.
//   - TLS verification stays on (InsecureSkipVerify is left false); MinVersion
//     is TLS 1.2.
//   - CheckRedirect returns ErrUseLastResponse, so no redirect is ever followed
//     (a 3xx cannot bounce the credentialed request to a non-allowed host).
//   - Proxy is disabled so environment proxy settings cannot exfiltrate the
//     request or bypass the IP check.
func newSecureHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			// address is "IP:port" with the host already resolved to a literal
			// IP by the dialer — this is the TOCTOU-safe checkpoint.
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("credential_http_request: cannot parse dial address")
			}
			ip := net.ParseIP(host)
			if testAllowLoopbackDial && ip != nil && ip.IsLoopback() {
				return nil // test seam only; false in production
			}
			if isBlockedIP(ip) {
				return fmt.Errorf("credential_http_request: connection to non-public address blocked")
			}
			return nil
		},
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if testTLSConfigHook != nil {
		testTLSConfigHook(tlsCfg)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          1,
		IdleConnTimeout:       time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// enforceHTTPSURL parses target and returns the host, requiring an https scheme
// with a non-empty host. Rejects http, opaque, and userinfo-bearing URLs.
func enforceHTTPSURL(target string) (host string, err error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target_url")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("target_url must use https")
	}
	if u.Host == "" {
		return "", fmt.Errorf("target_url has no host")
	}
	if u.User != nil {
		return "", fmt.Errorf("target_url must not embed credentials")
	}
	return u.Host, nil
}

// substituteSecretHeaders resolves every {{secret.<key>}} placeholder in the
// template values against secret and returns the assembled header values plus
// the distinct secret strings that were actually injected (used later for body
// redaction). A placeholder whose key is absent from the decrypted payload is an
// error — the request must not go out with an unresolved or empty credential.
func substituteSecretHeaders(template map[string]string, secret map[string]string) (map[string]string, []string, error) {
	assembled := make(map[string]string, len(template))
	injectedSet := map[string]bool{}
	var missing error

	for name, tmpl := range template {
		resolved := secretPlaceholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
			key := secretPlaceholderRe.FindStringSubmatch(match)[1]
			val, ok := secret[key]
			if !ok {
				missing = fmt.Errorf("header_template references unknown secret key %q", key)
				return match
			}
			if val != "" {
				injectedSet[val] = true
			}
			return val
		})
		if missing != nil {
			return nil, nil, missing
		}
		assembled[name] = resolved
	}

	injected := make([]string, 0, len(injectedSet))
	for v := range injectedSet {
		injected = append(injected, v)
	}
	// Longest first so a secret that is a substring of another is masked last
	// (deterministic ordering also keeps output stable).
	sort.Slice(injected, func(i, j int) bool { return len(injected[i]) > len(injected[j]) })
	return assembled, injected, nil
}

// redactResponseHeaders flattens http.Header into a string map, dropping the
// credential-bearing header names entirely (Authorization / Set-Cookie /
// Proxy-Authorization). Multi-value headers are joined with ", ".
func redactResponseHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, vals := range h {
		if redactedHeaderNames[http.CanonicalHeaderKey(name)] {
			continue
		}
		out[name] = strings.Join(vals, ", ")
	}
	return out
}

// redactionVariants returns common representations an HTTP endpoint can use
// when echoing a credential. In particular, HTTP/1 header bytes are sometimes
// decoded as Latin-1 and then JSON-escaped ("\\u00ed..."); literal-only
// replacement misses that reversible form. This is defense-in-depth for
// accidental echoes, not a claim that arbitrary transformations are detectable.
func redactionVariants(secret string) []string {
	raw := []byte(secret)
	set := map[string]struct{}{}
	add := func(value string) {
		if value != "" {
			set[value] = struct{}{}
		}
	}

	add(secret)
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))
	add(base64.StdEncoding.EncodeToString(raw))
	add(base64.RawStdEncoding.EncodeToString(raw))
	add(base64.URLEncoding.EncodeToString(raw))
	add(base64.RawURLEncoding.EncodeToString(raw))
	hexValue := hex.EncodeToString(raw)
	add(hexValue)
	add(strings.ToUpper(hexValue))

	// QuoteToASCII covers JSON-style Unicode escapes of the original string.
	add(strings.Trim(strconv.QuoteToASCII(secret), `"`))

	// Reproduce the common HTTP/1 bridge behaviour where each UTF-8 byte is
	// interpreted as a Latin-1 code point before JSON serialization.
	latin1Runes := make([]rune, len(raw))
	for i, b := range raw {
		latin1Runes[i] = rune(b)
	}
	latin1 := string(latin1Runes)
	add(latin1)
	add(strings.Trim(strconv.QuoteToASCII(latin1), `"`))

	variants := make([]string, 0, len(set))
	for value := range set {
		variants = append(variants, value)
	}
	sort.Slice(variants, func(i, j int) bool {
		if len(variants[i]) == len(variants[j]) {
			return variants[i] < variants[j]
		}
		return len(variants[i]) > len(variants[j])
	})
	return variants
}

// redactBody masks literal and common encoded echoes of injected secrets in
// the response body. Variants are longest-first so overlapping values redact
// deterministically.
func redactBody(body []byte, injected []string) []byte {
	for _, s := range injected {
		for _, variant := range redactionVariants(s) {
			body = bytes.ReplaceAll(body, []byte(variant), []byte(redactionMask))
		}
	}
	return body
}
