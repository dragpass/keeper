package keystore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	purgeFrame = `{"action":"chat_state_purge","request_id":"p-1","payload":{"owner_account_id":"a1111111-1111-4111-8111-111111111111"}}`
	resetFrame = `{"action":"reset_device_identity","request_id":"x-1","payload":{}}`
)

func revokedReason(t *testing.T, response proto.BaseResponse) string {
	t.Helper()
	if response.Success || response.ErrorCode != ErrCodeChatRuntimeRevoked {
		t.Fatalf("want %s, got %+v", ErrCodeChatRuntimeRevoked, response)
	}
	raw, _ := json.Marshal(response.Data)
	var data struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &data)
	return data.Reason
}

func claimed(t *testing.T, app *App, clock *leaseClock, holder, session, held string) string {
	t.Helper()
	claim := app.ClaimChatRuntime(holder, session, farSession(clock), held)
	if !claim.Granted || claim.Epoch == "" || claim.Revoked != "" {
		t.Fatalf("claim: %+v", claim)
	}
	return claim.Epoch
}

// The epoch moves only on a revocation: renewals, release and re-claim, and a
// Keeper restart over the same store all keep it, so a restart stays the
// lease_required -> reclaim path and never looks like a reset.
func TestChatRuntimeEpochIsStableWithoutARevocation(t *testing.T) {
	app, clock, store := newLeaseApp(t)
	epoch := claimed(t, app, clock, holderA, sessionA, "")
	if len(epoch) > 64 || strings.ContainsAny(epoch, " \r\n") {
		t.Fatalf("epoch %q is not a header-safe token", epoch)
	}
	if renewed := claimed(t, app, clock, holderA, sessionA, epoch); renewed != epoch {
		t.Fatalf("renewal moved the epoch: %q -> %q", epoch, renewed)
	}
	app.ReleaseChatRuntime(holderA)
	if again := claimed(t, app, clock, holderB, sessionB, ""); again != epoch {
		t.Fatalf("a re-claim moved the epoch: %q -> %q", epoch, again)
	}

	restarted := NewApp(Deps{Store: store, Clock: clock.Now})
	if after := claimed(t, restarted, clock, holderA, sessionA, epoch); after != epoch {
		t.Fatalf("a restart moved the epoch: %q -> %q", epoch, after)
	}
}

func TestChatRuntimeAppGatedCallWithoutAnEpochNeedsTheLease(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	claimed(t, app, clock, holderA, sessionA, "")
	if response := app.HandleAppRequest(sessionA, "", []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("a gated call without an epoch: %+v", response)
	}
}

// Extension logout wins over a live App lease: its purge is not refused busy,
// it revokes the epoch, and nothing the old holder sends afterwards runs.
func TestChatRuntimeExtensionRevocationWinsOverALiveAppLease(t *testing.T) {
	for _, tc := range []struct {
		name, frame, reason string
	}{
		{"purge", purgeFrame, ChatRuntimeRevokedPurged},
		{"reset", resetFrame, ChatRuntimeRevokedReset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, clock, store := newLeaseApp(t)
			epoch := claimed(t, app, clock, holderA, sessionA, "")
			if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); !response.Success {
				t.Fatalf("the holder's gated call: %+v", response)
			}
			if response := app.HandleRequest([]byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeBusy {
				t.Fatalf("an ordinary Extension gated call is still refused: %+v", response)
			}

			if response := app.HandleRequest([]byte(tc.frame)); !response.Success {
				t.Fatalf("Extension %s while the App holds the lease: %+v", tc.name, response)
			}

			before := store.calls.Load()
			if reason := revokedReason(t, app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame))); reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			if store.calls.Load() != before {
				t.Fatal("a revoked call ran")
			}
			if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), epoch); claim.Granted || claim.Revoked != tc.reason {
				t.Fatalf("re-claim with the revoked epoch: %+v", claim)
			}
			if response := app.HandleAppChatWrite(sessionA, epoch, []byte(`{"action":"ping"}`)); revokedReason(t, response) != tc.reason {
				t.Fatalf("chat write with the revoked epoch: %+v", response)
			}

			// A new runtime claims without an epoch, after the Extension window.
			if claim := app.ClaimChatRuntime(holderB, sessionB, farSession(clock), ""); claim.Granted || claim.BusyHolder != ChatRuntimeHolderExtension {
				t.Fatalf("claim inside the Extension window: %+v", claim)
			}
			clock.advance(ChatRuntimeExtensionWindow)
			fresh := claimed(t, app, clock, holderB, sessionB, "")
			if fresh == epoch {
				t.Fatal("the revocation did not move the epoch")
			}
			if response := app.HandleAppRequest(sessionB, fresh, []byte(gatedFrame)); !response.Success {
				t.Fatalf("the new runtime's gated call: %+v", response)
			}

			// A restart cannot bring the old epoch back.
			restarted := NewApp(Deps{Store: store, Clock: clock.Now})
			if claim := restarted.ClaimChatRuntime(holderA, sessionA, farSession(clock), epoch); claim.Granted || claim.Revoked != tc.reason {
				t.Fatalf("old epoch after a restart: %+v", claim)
			}
			if again := claimed(t, restarted, clock, holderB, sessionB, fresh); again != fresh {
				t.Fatalf("restart moved the epoch: %q -> %q", fresh, again)
			}
		})
	}
}

// The App's own purge revokes its runtime too, so nothing it still has in
// flight lands on the purged state.
func TestChatRuntimeAppPurgeRevokesItsOwnEpoch(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	epoch := claimed(t, app, clock, holderA, sessionA, "")
	if response := app.HandleAppRequest(sessionA, epoch, []byte(purgeFrame)); !response.Success {
		t.Fatalf("App purge: %+v", response)
	}
	if reason := revokedReason(t, app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame))); reason != ChatRuntimeRevokedPurged {
		t.Fatalf("reason = %q", reason)
	}
	if response := app.HandleAppRequest(sessionA, epoch, []byte(resetFrame)); revokedReason(t, response) != ChatRuntimeRevokedPurged {
		t.Fatalf("reset from the revoked App: %+v", response)
	}
}

// Q1: from the App reset_device_identity needs the lease like any gated action.
func TestChatRuntimeAppResetNeedsTheLease(t *testing.T) {
	app, _, store := newLeaseApp(t)
	before := store.calls.Load()
	if response := app.HandleAppRequest(sessionA, "", []byte(resetFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("App reset without the lease: %+v", response)
	}
	if store.calls.Load() != before {
		t.Fatal("a refused reset ran")
	}
}

// A chat write is signed only for the session holding a live lease at the
// current epoch.
func TestChatRuntimeChatWriteNeedsTheLeaseAndTheEpoch(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	ping := []byte(`{"action":"ping"}`)
	if response := app.HandleAppChatWrite(sessionA, "", ping); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("chat write without a lease: %+v", response)
	}
	epoch := claimed(t, app, clock, holderA, sessionA, "")
	if response := app.HandleAppChatWrite(sessionA, epoch, ping); !response.Success {
		t.Fatalf("chat write with the lease: %+v", response)
	}
	if response := app.HandleAppChatWrite(sessionB, epoch, ping); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("chat write from another session: %+v", response)
	}
	clock.advance(ChatRuntimeLeaseTTL)
	if response := app.HandleAppChatWrite(sessionA, epoch, ping); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("chat write after the lease lapsed: %+v", response)
	}
}
