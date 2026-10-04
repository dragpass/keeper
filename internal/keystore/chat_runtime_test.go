package keystore

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
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

func busyHolder(t *testing.T, response proto.BaseResponse) string {
	t.Helper()
	raw, _ := json.Marshal(response.Data)
	var data struct {
		Holder string `json:"holder"`
	}
	_ = json.Unmarshal(raw, &data)
	return data.Holder
}

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

func TestChatRuntimeAppLeaseRefusesExtensionGatedActionsAndRunsNothing(t *testing.T) {
	app, clock, store := newLeaseApp(t)
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); !claim.Granted {
		t.Fatal(claim)
	}
	for _, action := range []string{
		"mls_group_create", "mls_encrypt", "mls_decrypt_batch_for_app_display",
		"chat_state_read_outbox", "mls_leaf_declare", "mls_key_package_generate", "mls_leaf_abort",
	} {
		before := store.calls.Load()
		response := app.HandleRequest([]byte(`{"action":"` + action + `","request_id":"x","payload":{}}`))
		if response.Success || response.ErrorCode != ErrCodeChatRuntimeBusy || busyHolder(t, response) != ChatRuntimeHolderApp || response.RequestID != "x" {
			t.Fatalf("%s from the Extension while the App holds the lease: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s ran although it was refused", action)
		}
	}
	for _, action := range []string{"ping", "mls_leaf_status", "mls_conversation_status", "mls_room_name_open", "getpublickey"} {
		if response := app.HandleRequest([]byte(`{"action":"` + action + `"}`)); response.ErrorCode == ErrCodeChatRuntimeBusy {
			t.Fatalf("ungated %s was refused: %+v", action, response)
		}
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

func TestChatRuntimeExtensionActivityBlocksAnAppClaimForItsWindow(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	if response := app.HandleRequest([]byte(gatedFrame)); !response.Success {
		t.Fatalf("Extension gated action with no lease: %+v", response)
	}
	claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "")
	if claim.Granted || claim.BusyHolder != ChatRuntimeHolderExtension {
		t.Fatalf("claim right after Extension activity: %+v", claim)
	}
	// Ungated Extension traffic does not extend the window.
	clock.advance(ChatRuntimeExtensionWindow - time.Second)
	app.HandleRequest([]byte(`{"action":"ping"}`))
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); claim.Granted {
		t.Fatalf("claim inside the window: %+v", claim)
	}
	clock.advance(time.Second)
	if claim := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), ""); !claim.Granted {
		t.Fatalf("claim after the window: %+v", claim)
	}
}

func TestChatRuntimeLeaseExpiresAndDiesWithItsSession(t *testing.T) {
	app, clock, _ := newLeaseApp(t)
	epoch := app.ClaimChatRuntime(holderA, sessionA, farSession(clock), "").Epoch
	clock.advance(ChatRuntimeLeaseTTL - time.Second)
	if response := app.HandleRequest([]byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeBusy {
		t.Fatalf("Extension ran before the lease expired: %+v", response)
	}
	clock.advance(time.Second)
	if response := app.HandleAppRequest(sessionA, epoch, []byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("an expired lease still admits the App: %+v", response)
	}
	if response := app.HandleRequest([]byte(gatedFrame)); !response.Success {
		t.Fatalf("Extension after the lease expired: %+v", response)
	}

	// A lease never outlives the session it is bound to.
	app2, clock2, _ := newLeaseApp(t)
	claim := app2.ClaimChatRuntime(holderA, sessionA, 20*time.Second, "")
	if !claim.Granted || !claim.ExpiresAt.Equal(clock2.Now().Add(20*time.Second)) {
		t.Fatalf("lease past its session: %+v", claim)
	}
	clock2.advance(20 * time.Second)
	if response := app2.HandleRequest([]byte(gatedFrame)); !response.Success {
		t.Fatalf("the lease outlived its session: %+v", response)
	}

	// Deleting the session drops the lease at once.
	app3, clock3, _ := newLeaseApp(t)
	app3.ClaimChatRuntime(holderA, sessionA, farSession(clock3), "")
	app3.DropChatRuntimeSession(sessionB)
	if response := app3.HandleRequest([]byte(gatedFrame)); response.ErrorCode != ErrCodeChatRuntimeBusy {
		t.Fatal("dropping another session dropped the lease")
	}
	app3.DropChatRuntimeSession(sessionA)
	if response := app3.HandleRequest([]byte(gatedFrame)); !response.Success {
		t.Fatalf("the lease survived its session: %+v", response)
	}
	epoch3 := app3.ClaimChatRuntime(holderB, sessionB, farSession(clock3), "").Epoch
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

// An App claim and Extension gated calls race at one instant: never both.
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
		if claimed.Load() == (extensionRan.Load() > 0) {
			t.Fatalf("round %d: claimed=%v extension ran %d times", round, claimed.Load(), extensionRan.Load())
		}
	}
}
