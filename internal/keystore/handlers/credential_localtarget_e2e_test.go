//go:build keeper_e2e && keeper_e2e_localtarget

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"net"
	"strconv"
	"testing"
)

func configureLocalTarget(t *testing.T, ports, caFile string) {
	t.Helper()
	t.Setenv("KEEPER_E2E_LOCAL_TARGET_PORTS", ports)
	t.Setenv("KEEPER_E2E_LOCAL_TARGET_CA_FILE", caFile)
	resetLocalTargetConfigForTest()
	t.Cleanup(resetLocalTargetConfigForTest)
}

// An allowed loopback port, trusted only through the configured CA file.
func TestLocalTarget_AllowedPortWithConfiguredCAReachesTarget(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	configureLocalTarget(t, strconv.Itoa(s.port), s.caFile)
	deps, _, _ := newTestDeps(t)
	resp := HandleCredentialHTTPRequest(deps, localTargetRequest(t, deps, s))
	if !resp.Success {
		t.Fatalf("allowed local target refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
	if s.hits.Load() != 1 {
		t.Fatalf("target saw %d requests, want 1", s.hits.Load())
	}
}

// TLS verification stays on: without the CA file the test server's
// certificate is not trusted, even on an allowed port.
func TestLocalTarget_WithoutCATLSVerificationFails(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	configureLocalTarget(t, strconv.Itoa(s.port), "")
	deps, _, _ := newTestDeps(t)
	if resp := HandleCredentialHTTPRequest(deps, localTargetRequest(t, deps, s)); resp.Success {
		t.Fatal("an untrusted certificate was accepted")
	}
	if s.hits.Load() != 0 {
		t.Fatalf("target served %d requests over an unverified connection", s.hits.Load())
	}
}

func TestLocalTarget_PortNotInListIsRefusedBeforeConnecting(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	configureLocalTarget(t, strconv.Itoa(s.port+1), s.caFile)
	deps, _, _ := newTestDeps(t)
	if resp := HandleCredentialHTTPRequest(deps, localTargetRequest(t, deps, s)); resp.Success {
		t.Fatal("a port outside the list was reached")
	}
	if s.conns.Load() != 0 {
		t.Fatalf("target saw %d connections, want 0", s.conns.Load())
	}
}

func TestLocalTarget_OnlyLoopbackOnListedPorts(t *testing.T) {
	configureLocalTarget(t, "8443,9443", "")
	for addr, want := range map[string]bool{
		"127.0.0.1:8443":       true,
		"[::1]:9443":           true,
		"127.0.0.1:443":        false,
		"10.0.0.1:8443":        false,
		"192.168.1.1:8443":     false,
		"169.254.169.254:8443": false,
		"[fd00::1]:8443":       false,
		"8.8.8.8:8443":         false,
	} {
		host, portText, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portText)
		if got := localTargetDialAllowed(net.ParseIP(host), port); got != want {
			t.Errorf("localTargetDialAllowed(%s) = %v, want %v", addr, got, want)
		}
	}
	configureLocalTarget(t, "", "")
	if localTargetDialAllowed(net.ParseIP("127.0.0.1"), 8443) {
		t.Error("an empty port list allowed loopback")
	}
}

// The relaxation sits in the dial check only: a policy whose signature does
// not verify is refused before anything is dialled.
func TestLocalTarget_SignatureIsStillRequired(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	configureLocalTarget(t, strconv.Itoa(s.port), s.caFile)
	deps, _, _ := newTestDepsFailVerify(t, errors.New("bad signature"))
	if resp := HandleCredentialHTTPRequest(deps, localTargetRequest(t, deps, s)); resp.Success {
		t.Fatal("an unverified policy reached the local target")
	}
	if s.conns.Load() != 0 {
		t.Fatalf("target saw %d connections, want 0", s.conns.Load())
	}
}

// The local target changes the dial check only: one signed policy still runs
// once.
func TestLocalTarget_NonceIsStillSingleUse(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	configureLocalTarget(t, strconv.Itoa(s.port), s.caFile)
	deps, _, _ := newTestDeps(t)
	req := localTargetRequest(t, deps, s)
	if resp := HandleCredentialHTTPRequest(deps, req); !resp.Success {
		t.Fatalf("first submission refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
	resp := HandleCredentialHTTPRequest(deps, req)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeCredentialNonceInvalid) {
		t.Fatalf("second submission = %+v, want credential_nonce_invalid", resp)
	}
	if s.hits.Load() != 1 {
		t.Fatalf("target saw %d requests, want 1", s.hits.Load())
	}
}
