package localrpc

import (
	"encoding/json"
	"testing"
)

func releaseOver(t *testing.T, c *testAppClient, body map[string]string) bool {
	t.Helper()
	response, err := c.call("/v1/chat/runtime/release", body)
	if err != nil || !response.Success {
		t.Fatalf("release: %+v %v", response, err)
	}
	raw, _ := json.Marshal(response.Data)
	var decoded struct {
		Released bool `json:"released"`
	}
	_ = json.Unmarshal(raw, &decoded)
	return decoded.Released
}

// The real binary, two App sessions of one profile (one holder id): tab 1's
// release reaches Keeper only after tab 2 claimed, the order a lost or slow
// answer produces (lv74). Tab 2 keeps its lease; tab 1's release, bound to
// its own grant, ends nothing, and neither does an unbound one from an App
// before lv74.
func TestLateReleaseDoesNotEndANewerLeaseOverRealProcess(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	owner := startAppService(t, dir, address)
	tab1 := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	tab2 := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	for _, c := range []*testAppClient{tab1, tab2} {
		if err := c.open(); err != nil {
			t.Fatalf("open session: %v\n%s", err, owner.stderr.String())
		}
	}

	first, err := tab1.claim(routeHolder)
	if err != nil || !first.Success {
		t.Fatalf("tab 1 claim: %+v %v", first, err)
	}
	raw, _ := json.Marshal(first.Data)
	oldID := leaseIDOf(raw)
	second, err := tab2.claim(routeHolder)
	if err != nil || !second.Success {
		t.Fatalf("tab 2 claim: %+v %v", second, err)
	}
	raw, _ = json.Marshal(second.Data)
	newID := leaseIDOf(raw)
	if oldID == "" || newID == "" || oldID == newID {
		t.Fatalf("lease ids: %q %q", oldID, newID)
	}

	if releaseOver(t, tab1, map[string]string{"holder_id": routeHolder, "lease_id": oldID}) {
		t.Fatal("tab 1's late release ended tab 2's lease")
	}
	if releaseOver(t, tab1, map[string]string{"holder_id": routeHolder}) {
		t.Fatal("an unbound release ended tab 2's lease")
	}
	if ran, err := tab2.call("/v1/chat/mls_leaf_abort", map[string]any{}); err != nil || !leaseAdmitted(ran) {
		t.Fatalf("tab 2 lost its lease: %+v %v", ran, err)
	}

	// Tab 2 claims again (a renewal): its own earlier grant cannot be released.
	renewed, err := tab2.claim(routeHolder)
	if err != nil || !renewed.Success {
		t.Fatalf("tab 2 renewal: %+v %v", renewed, err)
	}
	raw, _ = json.Marshal(renewed.Data)
	renewedID := leaseIDOf(raw)
	if releaseOver(t, tab2, map[string]string{"holder_id": routeHolder, "lease_id": newID}) {
		t.Fatal("a release of tab 2's earlier grant ended its renewed lease")
	}
	if !releaseOver(t, tab2, map[string]string{"holder_id": routeHolder, "lease_id": renewedID}) {
		t.Fatal("tab 2 could not release its current lease")
	}
	if ran, err := tab2.call("/v1/chat/mls_leaf_abort", map[string]any{}); err != nil || leaseAdmitted(ran) {
		t.Fatalf("a released lease still admits gated work: %+v %v", ran, err)
	}
}
