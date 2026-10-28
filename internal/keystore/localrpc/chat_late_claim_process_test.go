package localrpc

import "testing"

// Characterization: requests delivered after a handover still carry the old
// session's authority to claim. Two deliberately ordered late claims distinguish
// one-off recovery from immunity to another outstanding request; no random loop.
func TestLateClaimsCanRepeatedlyRebindAfterRecoveryOverRealProcess(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	startAppService(t, dir, address)
	oldTab := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	newTab := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	for _, c := range []*testAppClient{oldTab, newTab} {
		if err := c.open(); err != nil {
			t.Fatal("session did not open")
		}
	}
	claim := func(c *testAppClient) {
		t.Helper()
		response, err := c.claim(routeHolder)
		if err != nil || !response.Success {
			t.Fatal("claim failed")
		}
	}
	admitted := func(c *testAppClient) bool {
		t.Helper()
		response, err := c.call("/v1/chat/mls_leaf_abort", map[string]any{})
		if err != nil {
			t.Fatal("gated operation transport failed")
		}
		return leaseAdmitted(response)
	}
	claim(oldTab)
	claim(newTab)
	if !admitted(newTab) {
		t.Fatal("new owner was not admitted")
	}
	// First late delivery, then explicit recovery by the new session.
	claim(oldTab)
	if admitted(newTab) {
		t.Fatal("new session unexpectedly kept the lease")
	}
	claim(newTab)
	if !admitted(newTab) {
		t.Fatal("first recovery failed")
	}
	// A second request already outstanding can repeat the interruption.
	claim(oldTab)
	if admitted(newTab) {
		t.Fatal("second late claim did not rebind")
	}
	claim(newTab)
	if !admitted(newTab) {
		t.Fatal("second recovery failed")
	}
	t.Log("ordered late claims=2; lease refusals=2; explicit recoveries=2")
}
