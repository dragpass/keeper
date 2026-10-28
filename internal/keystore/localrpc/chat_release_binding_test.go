package localrpc

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// A release ends only the lease it was sent for (lv74). The App's holder id
// is profile-wide, so tabs of one profile share it; each tab has its own
// session. A release Keeper processes late must never end a newer lease.

func leaseIDOf(data json.RawMessage) string {
	var decoded struct {
		LeaseID string `json:"lease_id"`
	}
	_ = json.Unmarshal(data, &decoded)
	return decoded.LeaseID
}

func releaseLease(t *testing.T, server *Server, session, csrf string, body map[string]string) bool {
	t.Helper()
	code, result, raw := callRoute(t, server, session, csrf, "/v1/chat/runtime/release", body)
	if code != http.StatusOK || !result.Success {
		t.Fatalf("release %v: %d %s", body, code, raw)
	}
	var decoded struct {
		Released bool `json:"released"`
	}
	_ = json.Unmarshal(result.Data, &decoded)
	return decoded.Released
}

func gatedAdmitted(t *testing.T, server *Server, session, csrf string) bool {
	t.Helper()
	_, result, _ := callRoute(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{})
	return result.ErrorCode != "chat_runtime_lease_required" && result.ErrorCode != "chat_runtime_busy"
}

// Tab 1 claims, tab 2 of the same profile (same holder, another session)
// claims; tab 1's release then arrives. It must not end tab 2's lease.
func TestChatRuntimeLateReleaseFromAnotherSessionKeepsTheNewerLease(t *testing.T) {
	server, _ := newChatTestServer(t)
	first, firstCSRF := openTestSession(t, server)
	second, secondCSRF := openTestSession(t, server)

	old := claimLease(t, server, first, firstCSRF, routeHolder)
	oldID := leaseIDOf(old.Data)
	if !old.Success || oldID == "" {
		t.Fatalf("first claim names no lease: %+v %s", old, old.Data)
	}
	newer := claimLease(t, server, second, secondCSRF, routeHolder)
	if !newer.Success || leaseIDOf(newer.Data) == "" || leaseIDOf(newer.Data) == oldID {
		t.Fatalf("second claim: %+v %s", newer, newer.Data)
	}

	if releaseLease(t, server, first, firstCSRF, map[string]string{"holder_id": routeHolder, "lease_id": oldID}) {
		t.Fatal("a late release from the old session ended the newer lease")
	}
	// An App from before lv74 sends no lease id: it never ends a lease.
	if releaseLease(t, server, first, firstCSRF, map[string]string{"holder_id": routeHolder}) {
		t.Fatal("an unbound release ended the newer lease")
	}
	if !gatedAdmitted(t, server, second, secondCSRF) {
		t.Fatal("the newer lease is gone")
	}
	if !releaseLease(t, server, second, secondCSRF, map[string]string{"holder_id": routeHolder, "lease_id": leaseIDOf(newer.Data)}) {
		t.Fatal("the holder of the newer lease could not release it")
	}
	if gatedAdmitted(t, server, second, secondCSRF) {
		t.Fatal("a released lease still admits gated work")
	}
}

// One session: its release is delayed, it claims again (a renewal, or a new
// lease after the old one lapsed), then the old release arrives. It must not
// end the lease the later claim got.
func TestChatRuntimeLateReleaseInTheSameSessionKeepsTheLaterClaim(t *testing.T) {
	for _, lapse := range []bool{false, true} {
		server, clock := newChatTestServer(t)
		session, csrf := openTestSession(t, server)

		old := claimLease(t, server, session, csrf, routeHolder)
		oldID := leaseIDOf(old.Data)
		if lapse {
			clock.advance(61 * time.Second)
		} else {
			clock.advance(20 * time.Second)
		}
		later := claimLease(t, server, session, csrf, routeHolder)
		if !later.Success || leaseIDOf(later.Data) == "" || leaseIDOf(later.Data) == oldID {
			t.Fatalf("lapse=%v: the later claim did not get its own lease id: %s", lapse, later.Data)
		}
		if releaseLease(t, server, session, csrf, map[string]string{"holder_id": routeHolder, "lease_id": oldID}) {
			t.Fatalf("lapse=%v: the old release ended the later lease", lapse)
		}
		if !gatedAdmitted(t, server, session, csrf) {
			t.Fatalf("lapse=%v: the later lease is gone", lapse)
		}
	}
}

func TestChatRuntimeReleaseRefusesAMalformedLeaseID(t *testing.T) {
	server, _ := newChatTestServer(t)
	session, csrf := openTestSession(t, server)
	claimLease(t, server, session, csrf, routeHolder)
	for _, bad := range []string{"short", "has space in it but long enough", "padded+base64/value=========="} {
		code, _, _ := callRoute(t, server, session, csrf, "/v1/chat/runtime/release", map[string]string{"holder_id": routeHolder, "lease_id": bad})
		if code != http.StatusBadRequest {
			t.Fatalf("release with lease id %q: %d", bad, code)
		}
	}
}
