package keystore

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// countingStore records every keychain access, so a refused request can be
// shown to have run nothing.
type countingStore struct {
	SecretStore
	calls atomic.Int32
}

func (s *countingStore) Get(service, account string) (string, error) {
	s.calls.Add(1)
	return s.SecretStore.Get(service, account)
}

func (s *countingStore) Set(service, account, value string) error {
	s.calls.Add(1)
	return s.SecretStore.Set(service, account, value)
}

func (s *countingStore) Delete(service, account string) error {
	s.calls.Add(1)
	return s.SecretStore.Delete(service, account)
}

type leaseClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *leaseClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *leaseClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newLeaseApp(t *testing.T) (*App, *leaseClock, *countingStore) {
	t.Helper()
	clock := &leaseClock{now: time.Unix(1_800_000_000, 0)}
	store := &countingStore{SecretStore: testdouble.NewMemorySecretStore()}
	return NewApp(Deps{Store: store, Clock: clock.Now}), clock, store
}

const (
	holderA   = "aG9sZGVyLWEtMTZieXRlcw"
	holderB   = "aG9sZGVyLWItMTZieXRlcw"
	sessionA  = "session-a"
	sessionA2 = "session-a-reopened"
	sessionB  = "session-b"
)

// gatedFrame is an action the lease guards that touches the keychain when it
// runs, so a refusal is visible as zero store calls.
const gatedFrame = `{"action":"mls_leaf_abort","request_id":"r-1","payload":{}}`

func farSession(*leaseClock) time.Duration { return 10 * time.Minute }

func TestChatRuntimeClaimRenewRebindAndRelease(t *testing.T) {
	app, clock, _ := newLeaseApp(t)

	claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "")
	if !claim.Granted || !claim.ExpiresAt.Equal(clock.Now().Add(ChatRuntimeLeaseTTL)) {
		t.Fatalf("first claim: %+v", claim)
	}
	clock.advance(30 * time.Second)
	renewed := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "")
	if !renewed.Granted || !renewed.ExpiresAt.Equal(clock.Now().Add(ChatRuntimeLeaseTTL)) {
		t.Fatalf("renew: %+v", renewed)
	}
	if other := app.ClaimChatRuntime(holderB, sessionB, farSession(clock), ""); other.Granted || other.BusyHolder != ChatRuntimeHolderApp {
		t.Fatalf("another holder took a live lease: %+v", other)
	}

	// The same holder from a reopened session moves the lease to that session.
	if rebound := app.ClaimChatRuntime(holderA, sessionA2, farSession(clock), ""); !rebound.Granted {
		t.Fatalf("rebind: %+v", rebound)
	}
	if response := app.HandleAppRequest(sessionA, claim.Epoch, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("the old session still holds the lease: %+v", response)
	}
	if response := app.HandleAppRequest(sessionA2, claim.Epoch, []byte(gatedFrame)); !response.Success {
		t.Fatalf("the rebound session cannot run a gated action: %+v", response)
	}

	if app.ReleaseChatRuntime(holderB) {
		t.Fatal("another holder released the lease")
	}
	if !app.ReleaseChatRuntime(holderA) {
		t.Fatal("the holder could not release its lease")
	}
	if app.ReleaseChatRuntime(holderA) {
		t.Fatal("a released lease was released twice")
	}
	if claim := app.ClaimChatRuntime(holderB, sessionB, farSession(clock), ""); !claim.Granted {
		t.Fatalf("claim after release: %+v", claim)
	}
}

// Chat runs only in the App: a Native Messaging frame is refused every
// App-only action with or without a live App lease, and nothing runs.
func TestChatRuntimeRefusesExtensionAppOnlyActionsAndRunsNothing(t *testing.T) {
	for _, leased := range []bool{false, true} {
		app, clock, store := newLeaseApp(t)
		if leased {
			if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); !claim.Granted {
				t.Fatal(claim)
			}
		}
		for _, action := range dispatch.AppOnlyActions() {
			before := store.calls.Load()
			response := app.HandleRequest([]byte(`{"action":"` + action + `","request_id":"x","payload":{}}`))
			if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired || response.RequestID != "x" {
				t.Fatalf("%s from the Extension (leased=%v): %+v", action, leased, response)
			}
			if store.calls.Load() != before {
				t.Fatalf("%s ran although it was refused", action)
			}
		}
		for _, action := range []string{"ping", "org_member_removal_sign", "getpublickey", "peer_key_pin_get", "rotate_user_keypair_status"} {
			response := app.HandleRequest([]byte(`{"action":"` + action + `"}`))
			if response.ErrorCode == ErrCodeChatAppCallerRequired || response.ErrorCode == ErrCodeChatRuntimeBusy {
				t.Fatalf("%s was refused to the Extension (leased=%v): %+v", action, leased, response)
			}
		}
	}
}

// The App-only set is pinned: every gated action but the two revocations,
// the room name display open, the Secure Message seal and display, the
// organization emergency code seed derivation, the App session refresh
// signature, account entry, and the actions only App routes call
// (appRouteOnlyActions).
func TestChatRuntimeAppOnlyActionListIsPinned(t *testing.T) {
	want := []string{
		"account_archive_key_generate", "account_binding_set", "account_binding_signout",
		"archive_key_rotate_abort", "archive_key_rotate_begin", "archive_key_rotate_commit",
		"archive_key_split", "archive_key_status", "archive_quorum_combine_and_rewrap",
		"archive_session_begin", "archive_session_end", "archive_share_rewrap",
		"archive_unwrap_and_rewrap",
		"auth_login_pending_sign_alias", "auth_login_pending_sign_challenge",
		"auth_recovery_abort", "auth_recovery_begin", "auth_recovery_prepare",
		"auth_recovery_reissue_prepare", "auth_signup_abort", "auth_signup_prepare",
		"chat_state_read_outbox",
		"dek_rewrap_with_old_key_to_self", "dek_rotate_to_device_key", "dek_rotate_to_new_password",
		"group_decrypt_with_aad_for_app_display",
		"message_display_prepare", "message_seal",
		"mls_commit_build", "mls_commit_confirm",
		"mls_conversation_forget_removed", "mls_conversation_status",
		"mls_decrypt_batch_for_app_display", "mls_device_revoke_sign", "mls_encrypt",
		"mls_epoch_comparison",
		"mls_group_create", "mls_group_discard_unaccepted", "mls_join",
		"mls_key_package_generate",
		"mls_leaf_abort", "mls_leaf_declare", "mls_leaf_handover_sign", "mls_leaf_promote",
		"mls_leaf_status", "mls_leave_request_sign",
		"mls_mark_sent", "mls_process", "mls_rejoin_request_sign",
		"mls_room_name_open", "mls_room_name_seal",
		"org_emergency_seed_derive",
		"peer_key_chain_evaluate", "peer_key_pin_list", "peer_key_pin_verify", "peer_key_safety_number",
		"recovery_session_close",
		"rotate_user_keypair_prepare", "rotate_user_keypair_promote",
		"savesessioncode",
		"sign_app_session_refresh",
	}
	if got := dispatch.AppOnlyActions(); !slices.Equal(got, want) {
		t.Fatalf("App-only actions = %v", got)
	}
}

func TestChatRuntimeAppCallerNeedsTheLeaseForGatedActions(t *testing.T) {
	app, clock, store := newLeaseApp(t)
	before := store.calls.Load()
	response := app.HandleAppRequest(sessionA, "", []byte(gatedFrame))
	if response.Success || response.ErrorCode != ErrCodeChatRuntimeLeaseRequired || response.RequestID != "r-1" {
		t.Fatalf("gated action without a lease: %+v", response)
	}
	if store.calls.Load() != before {
		t.Fatal("a refused App request ran")
	}
	if response := app.HandleAppRequest(sessionA, "", []byte(`{"action":"ping"}`)); !response.Success {
		t.Fatalf("ping needs no lease: %+v", response)
	}
	if response := app.HandleAppRequest("", "", []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("a caller with no session ran a gated action: %+v", response)
	}
	epoch := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "").Epoch
	if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); !response.Success {
		t.Fatalf("gated action with the lease: %+v", response)
	}
	if response := app.HandleAppRequest(sessionB, epoch, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("another session used the lease: %+v", response)
	}
}

func TestChatRuntimeExtensionRevocationBlocksAnAppClaimForItsWindow(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	if response := app.HandleRequest([]byte(purgeFrame)); !response.Success {
		t.Fatalf("Extension purge with no lease: %+v", response)
	}
	claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "")
	if claim.Granted || claim.BusyHolder != ChatRuntimeHolderExtension {
		t.Fatalf("claim right after Extension activity: %+v", claim)
	}
	// Refused and ungated Extension traffic does not extend the window.
	clock.advance(ChatRuntimeExtensionWindow - time.Second)
	app.HandleRequest([]byte(`{"action":"ping"}`))
	app.HandleRequest([]byte(gatedFrame))
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); claim.Granted {
		t.Fatalf("claim inside the window: %+v", claim)
	}
	clock.advance(time.Second)
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); !claim.Granted {
		t.Fatalf("claim after the window: %+v", claim)
	}
}

// A refused Extension frame leaves no activity behind: the App claims at once.
func TestChatRuntimeRefusedExtensionFrameDoesNotBlockAnAppClaim(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	if response := app.HandleRequest([]byte(gatedFrame)); response.ErrorCode != ErrCodeChatAppCallerRequired {
		t.Fatalf("Extension gated action with no lease: %+v", response)
	}
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); !claim.Granted {
		t.Fatalf("claim after a refused Extension frame: %+v", claim)
	}
}

func TestChatRuntimeLeaseExpiresAndDiesWithItsSession(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	epoch := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "").Epoch
	clock.advance(ChatRuntimeLeaseTTL - time.Second)
	if claim := app.ClaimChatRuntime(holderB, sessionB, farSession(clock), ""); claim.Granted {
		t.Fatalf("another holder claimed before the lease expired: %+v", claim)
	}
	clock.advance(time.Second)
	if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("an expired lease still admits the App: %+v", response)
	}
	if claim := app.ClaimChatRuntime(holderB, sessionB, farSession(clock), ""); !claim.Granted {
		t.Fatalf("claim after the lease expired: %+v", claim)
	}

	// A lease never outlives the session it is bound to.
	app2, clock2, _ := newLeaseApp(t)
	claim := app2.ClaimChatRuntime(holderA, sessionA, 20*time.Second, "")
	if !claim.Granted || !claim.ExpiresAt.Equal(clock2.Now().Add(20*time.Second)) {
		t.Fatalf("lease past its session: %+v", claim)
	}
	clock2.advance(20 * time.Second)
	if response := app2.HandleAppRequest(sessionA, claim.Epoch, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("the lease outlived its session: %+v", response)
	}

	// Deleting the session drops the lease at once.
	app3, clock3, _ := newLeaseApp(t)
	epoch3 := app3.ClaimChatRuntime(holderA, sessionA, farSession(clock3), "").Epoch
	app3.DropChatRuntimeSession(sessionB)
	if response := app3.HandleAppRequest(sessionA, epoch3, []byte(gatedFrame)); !response.Success {
		t.Fatalf("dropping another session dropped the lease: %+v", response)
	}
	app3.DropChatRuntimeSession(sessionA)
	if response := app3.HandleAppRequest(sessionA, epoch3, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("the lease survived its session: %+v", response)
	}
	epoch3 = app3.ClaimChatRuntime(holderB, sessionB, farSession(clock3), "").Epoch
	app3.DropAllChatRuntimeSessions()
	if response := app3.HandleAppRequest(sessionB, epoch3, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("the lease survived dropping every session: %+v", response)
	}
}

// The gate is the exact list the contract names; the pin keeps a new chat
// writer from going ungated by omission.
func TestChatRuntimeGatedActionListIsPinned(t *testing.T) {
	want := []string{
		"chat_state_purge", "chat_state_read_outbox",
		"mls_commit_build", "mls_commit_confirm",
		"mls_conversation_forget_removed", "mls_decrypt_batch_for_app_display", "mls_encrypt",
		"mls_group_create", "mls_group_discard_unaccepted", "mls_join",
		"mls_key_package_generate",
		"mls_leaf_abort", "mls_leaf_declare", "mls_leaf_promote",
		"mls_mark_sent", "mls_process", "reset_device_identity",
	}
	got := ChatRuntimeGatedActions()
	if len(got) != len(want) {
		t.Fatalf("gated actions = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("gated actions = %v", got)
		}
	}
}

// Two App holders claim at once: exactly one wins.
func TestChatRuntimeConcurrentClaimsHaveOneWinner(t *testing.T) {
	for round := 0; round < 50; round++ {
		app, clock, _ := newLeaseApp(t)
		var granted atomic.Int32
		var start, done sync.WaitGroup
		start.Add(1)
		for i, holder := range []string{holderA, holderB, "aG9sZGVyLWMtMTZieXRlcw", "aG9sZGVyLWQtMTZieXRlcw"} {
			done.Add(1)
			go func(i int, holder string) {
				defer done.Done()
				start.Wait()
				if app.ClaimChatRuntime(holder, sessionA+string(rune('0'+i)), farSession(clock), "").Granted {
					granted.Add(1)
				}
			}(i, holder)
		}
		start.Done()
		done.Wait()
		if granted.Load() != 1 {
			t.Fatalf("round %d: %d holders won the lease", round, granted.Load())
		}
	}
}

// An App claim and Extension gated calls race at one instant: the Extension
// never runs and the claim always wins.
func TestChatRuntimeClaimAndExtensionCallsNeverBothSucceed(t *testing.T) {
	for round := 0; round < 50; round++ {
		app, clock, _ := newLeaseApp(t)
		var claimed atomic.Bool
		var extensionRan atomic.Int32
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			claimed.Store(app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "").Granted)
		}()
		for range 4 {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				if app.HandleRequest([]byte(gatedFrame)).Success {
					extensionRan.Add(1)
				}
			}()
		}
		start.Done()
		done.Wait()
		if !claimed.Load() || extensionRan.Load() != 0 {
			t.Fatalf("round %d: claimed=%v extension ran %d times", round, claimed.Load(), extensionRan.Load())
		}
	}
}
