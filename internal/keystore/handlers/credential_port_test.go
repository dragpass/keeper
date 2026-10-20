// credential_port_test.go — a target is (https, hostname, effective port). An
// authority without a port means 443; any other port must be signed.

package handlers

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
)

func TestEffectivePort_OmittedAnd443AreTheSameTarget(t *testing.T) {
	p := credTestPolicy([]string{"api.example.com:443"}, []string{"GET"})
	p.TargetPath = "/x"
	if !executionTargetMatches("https://API.Example.com/x", "GET", p) {
		t.Error("an omitted port did not match a target signed with :443")
	}
	if !hostAllowed("api.example.com", p.AllowedHosts) {
		t.Error("an omitted port was not in allowed_hosts [api.example.com:443]")
	}
	p = credTestPolicy([]string{"api.example.com"}, []string{"GET"})
	p.TargetPath = "/x"
	if !executionTargetMatches("https://api.example.com:443/x", "GET", p) {
		t.Error(":443 did not match a target signed without a port")
	}
	if !hostAllowed("api.example.com:443", p.AllowedHosts) {
		t.Error(":443 was not in allowed_hosts [api.example.com]")
	}
}

func TestEffectivePort_OtherPortsMustBeSigned(t *testing.T) {
	p := credTestPolicy([]string{"api.example.com"}, []string{"GET"})
	p.TargetPath = "/x"
	if executionTargetMatches("https://api.example.com:8443/x", "GET", p) {
		t.Error("a default-port target matched :8443")
	}
	if hostAllowed("api.example.com:8443", p.AllowedHosts) {
		t.Error("allowed_hosts [api.example.com] allowed :8443")
	}
	p = credTestPolicy([]string{"api.example.com:8443"}, []string{"GET"})
	p.TargetPath = "/x"
	if !executionTargetMatches("https://api.example.com:8443/x", "GET", p) {
		t.Error("a :8443 target did not match its own port")
	}
	if executionTargetMatches("https://api.example.com/x", "GET", p) {
		t.Error("a :8443 target matched the default port")
	}
	if !hostAllowed("[2001:DB8::1]:443", []string{"[2001:db8::1]"}) {
		t.Error("an IPv6 literal with :443 did not match the same literal without a port")
	}
}

// A policy signed for the default port, used against a server on another
// port: refused before the payload opens, and the server sees no connection.
func TestCredentialHTTP_DefaultPortPolicyAtAnotherPortNeverDials(t *testing.T) {
	var conns, hits atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	prev, prevLoop := testTLSConfigHook, testAllowLoopbackDial
	testTLSConfigHook = func(cfg *tls.Config) {
		cfg.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	testAllowLoopbackDial = true
	t.Cleanup(func() { testTLSConfigHook, testAllowLoopbackDial = prev, prevLoop })

	deps, _, _ := newTestDeps(t)
	s := &singleUseServer{url: ts.URL}
	req := singleUseRequest(t, deps, s, "", nil, mintCredentialNonce(t, deps))
	// Sign the bare hostname: effective port 443, not the test server's port.
	req.Policy.TargetHost = "127.0.0.1"
	req.Policy.AllowedHosts = []string{"127.0.0.1"}

	requireRefused(t, HandleCredentialHTTPRequest(deps, req), errs.ErrCodeValidation)
	if conns.Load() != 0 || hits.Load() != 0 {
		t.Fatalf("target saw %d connections and %d requests, want none", conns.Load(), hits.Load())
	}
}
