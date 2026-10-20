//go:build !(keeper_e2e && keeper_e2e_localtarget)

package handlers

import (
	"net"
	"strconv"
	"testing"
)

// Outside the keeper_e2e_localtarget build the two variables mean nothing:
// loopback stays blocked before any connection and no extra root is trusted.
func TestLocalTarget_ReleaseRefusesLoopbackAndTrustsNoTestCA(t *testing.T) {
	requireNoLocalTargetSeams(t)
	s := newLocalTargetServer(t)
	t.Setenv("KEEPER_E2E_LOCAL_TARGET_PORTS", strconv.Itoa(s.port))
	t.Setenv("KEEPER_E2E_LOCAL_TARGET_CA_FILE", s.caFile)

	if localTargetDialAllowed(net.ParseIP("127.0.0.1"), s.port) {
		t.Fatal("a release build allowed a loopback dial")
	}
	if localTargetRootCAs() != nil {
		t.Fatal("a release build added a root CA")
	}
	deps, _, _ := newTestDeps(t)
	if resp := HandleCredentialHTTPRequest(deps, localTargetRequest(t, deps, s)); resp.Success {
		t.Fatal("a release build reached a loopback target")
	}
	if s.conns.Load() != 0 || s.hits.Load() != 0 {
		t.Fatalf("target saw %d connections, %d requests; want none", s.conns.Load(), s.hits.Load())
	}
}
