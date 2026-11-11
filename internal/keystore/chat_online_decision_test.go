package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// lv78 K3: the App lease alone no longer admits a protected MLS action. A
// call that arrives on the action's own route, without a verified decision,
// is refused before its handler runs.
func TestProtectedMLSActionWithoutADecisionIsRefused(t *testing.T) {
	for _, action := range []string{"mls_decrypt_batch_for_app_display", "mls_encrypt"} {
		t.Run(action, func(t *testing.T) {
			app, clock, _ := newLeaseApp(t)
			epoch := claimed(t, app, clock, holderA, sessionA, "")
			frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "r-1", "payload": map[string]any{}})
			response := app.HandleAppFencedRequest(sessionA, epoch, "", true, frame)
			if response.Success || response.ErrorCode != ErrCodeChatOnlineDecisionRequired {
				t.Fatalf("%s without a decision: %+v", action, response)
			}
		})
	}
}

const (
	onlineAccount = "a1111111-1111-4111-8111-111111111111"
	onlineDevice  = "d4444444-4444-4444-8444-444444444444"
	onlineToken   = "e5555555-5555-4555-8555-555555555555"
	onlineOrg     = "b2222222-2222-4222-8222-222222222222"
	onlineConv    = "c3333333-3333-4333-8333-333333333333"
	onlineSession = int64(1788998000123456789)
)

// onlineFixture is a Keeper signed in as onlineAccount on onlineDevice,
// pinning a test server key at version 1, with a granted App lease.
type onlineFixture struct {
	app   *App
	clock *leaseClock
	store *countingStore
	key   *rsa.PrivateKey
	epoch string
}

func newOnlineFixture(t *testing.T) *onlineFixture {
	t.Helper()
	app, clock, store := newLeaseApp(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err := keychain.SaveServerPublicKeyForVersion(store, 1, pemKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.DeviceID, onlineDevice); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keychain.SetAccountBinding(store, onlineAccount, "alice", true); err != nil {
		t.Fatal(err)
	}
	epoch := claimed(t, app, clock, holderA, sessionA, "")
	return &onlineFixture{app: app, clock: clock, store: store, key: key, epoch: epoch}
}

// onlineRequest is an mls_encrypt request for onlineConv. Its permit is not
// server-signed, so the handler refuses it: reaching that refusal shows the
// online gate admitted the call.
func onlineRequest(conversation string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"permit": map[string]any{
			"account_id": onlineAccount, "org_id": onlineOrg, "conversation_id": conversation,
			"issued_at": 1, "expires_at": 301, "server_key_version": 1, "signature": "AA==",
		},
		"org_id": onlineOrg, "conversation_id": conversation,
		"client_message_id": "m-1", "expected_epoch": 1, "plaintext_b64": "aGk=",
	})
	return raw
}

func (f *onlineFixture) prepare(t *testing.T, action string, request json.RawMessage) proto.ChatOnlinePrepareResponseData {
	t.Helper()
	response := f.app.PrepareChatOnline("", proto.ChatOnlinePrepareRequest{
		Action: action, Request: request, TokenID: onlineToken, SessionIssuedAtNanos: onlineSession,
	})
	if !response.Success {
		t.Fatalf("prepare: %+v", response)
	}
	data, ok := response.Data.(proto.ChatOnlinePrepareResponseData)
	if !ok || data.Challenge == "" || len(data.RequestCommitment) != 64 {
		t.Fatalf("prepare data: %+v", response.Data)
	}
	return data
}

// decide is what the API signs for prepared, at the fixture clock.
func (f *onlineFixture) decide(t *testing.T, action string, prepared proto.ChatOnlinePrepareResponseData) proto.ChatOnlineDecision {
	t.Helper()
	now := f.clock.Now().Unix()
	d := proto.ChatOnlineDecision{
		Challenge: prepared.Challenge, AccountID: onlineAccount, DeviceID: onlineDevice,
		TokenID: onlineToken, SessionIssuedAtNanos: onlineSession, Action: action,
		OrgID: onlineOrg, ConversationID: onlineConv, RequestCommitment: prepared.RequestCommitment,
		IssuedAt: now, ExpiresAt: now + 10, ServerKeyVersion: 1,
	}
	return f.sign(t, d)
}

func (f *onlineFixture) sign(t *testing.T, d proto.ChatOnlineDecision) proto.ChatOnlineDecision {
	t.Helper()
	sum := sha256.Sum256([]byte(proto.ChatOnlineDecisionCanonical(d)))
	sig, err := rsa.SignPSS(rand.Reader, f.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = base64.StdEncoding.EncodeToString(sig)
	return d
}

func (f *onlineFixture) execute(action string, request json.RawMessage, d proto.ChatOnlineDecision) proto.BaseResponse {
	return f.app.ExecuteChatOnline(sessionA, f.epoch, "", proto.ChatOnlineExecuteRequest{Action: action, Request: request, Decision: &d})
}

// admitted reports whether the online gate let the call reach its handler:
// the request's unsigned permit is the handler's own refusal.
func admitted(response proto.BaseResponse) bool {
	return !response.Success && strings.HasPrefix(response.ErrorCode, "CHAT_STATE_")
}

// lv78 K2: a decision the API signed for the challenge Keeper minted, bound
// to this account, device, session, action, conversation and request, admits
// exactly that call.
func TestValidOnlineDecisionAdmitsTheCall(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	prepared := f.prepare(t, "mls_encrypt", request)
	response := f.execute("mls_encrypt", request, f.decide(t, "mls_encrypt", prepared))
	if !admitted(response) {
		t.Fatalf("a valid decision was refused: %+v", response)
	}
}

func refusedByDecision(t *testing.T, response proto.BaseResponse) {
	t.Helper()
	if response.Success || response.ErrorCode != ErrCodeChatOnlineDecisionRefused {
		t.Fatalf("want %s, got %+v", ErrCodeChatOnlineDecisionRefused, response)
	}
}

// lv78 K1: only the pinned server key admits; a decision signed by any other
// key is refused.
func TestOnlineDecisionSignedByAnotherKeyIsRefused(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	prepared := f.prepare(t, "mls_encrypt", request)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pinned := f.key
	f.key = other
	forged := f.decide(t, "mls_encrypt", prepared)
	f.key = pinned
	refusedByDecision(t, f.execute("mls_encrypt", request, forged))
}

// lv78 K2: every bound field must equal what the challenge was minted for.
// Each case re-signs a decision that differs in one field, as an API that
// was asked about something else would.
func TestOnlineDecisionBoundToSomethingElseIsRefused(t *testing.T) {
	for name, change := range map[string]func(*proto.ChatOnlineDecision){
		"account":       func(d *proto.ChatOnlineDecision) { d.AccountID = "a9999999-1111-4111-8111-111111111111" },
		"device":        func(d *proto.ChatOnlineDecision) { d.DeviceID = "d9999999-4444-4444-8444-444444444444" },
		"token":         func(d *proto.ChatOnlineDecision) { d.TokenID = "e9999999-5555-4555-8555-555555555555" },
		"session start": func(d *proto.ChatOnlineDecision) { d.SessionIssuedAtNanos++ },
		"org":           func(d *proto.ChatOnlineDecision) { d.OrgID = "b9999999-2222-4222-8222-222222222222" },
		"conversation":  func(d *proto.ChatOnlineDecision) { d.ConversationID = "c9999999-3333-4333-8333-333333333333" },
		"action":        func(d *proto.ChatOnlineDecision) { d.Action = "mls_decrypt_batch_for_app_display" },
		"commitment":    func(d *proto.ChatOnlineDecision) { d.RequestCommitment = strings.Repeat("ab", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			request := onlineRequest(onlineConv)
			prepared := f.prepare(t, "mls_encrypt", request)
			d := f.decide(t, "mls_encrypt", prepared)
			change(&d)
			refusedByDecision(t, f.execute("mls_encrypt", request, f.sign(t, d)))
		})
	}
}

// lv78 K2: the decision admits the request it was prepared for, byte for
// byte, and only as the action it was prepared for.
func TestOnlineDecisionForAnotherRequestIsRefused(t *testing.T) {
	t.Run("changed request", func(t *testing.T) {
		f := newOnlineFixture(t)
		request := onlineRequest(onlineConv)
		d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
		changed := json.RawMessage(strings.Replace(string(request), `"aGk="`, `"aGkh"`, 1))
		refusedByDecision(t, f.execute("mls_encrypt", changed, d))
	})
	t.Run("other action", func(t *testing.T) {
		f := newOnlineFixture(t)
		request := onlineRequest(onlineConv)
		d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
		refusedByDecision(t, f.execute("mls_mark_sent", request, d))
	})
}

// lv78 K2: the wall-clock window of the decision holds, with the 5-second
// allowance only for an issue time ahead of this device's clock.
func TestOnlineDecisionOutsideItsWindowIsRefused(t *testing.T) {
	for name, shift := range map[string]int64{"expired": -10, "issued too far ahead": 6} {
		t.Run(name, func(t *testing.T) {
			f := newOnlineFixture(t)
			request := onlineRequest(onlineConv)
			d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
			d.IssuedAt += shift
			d.ExpiresAt += shift
			refusedByDecision(t, f.execute("mls_encrypt", request, f.sign(t, d)))
		})
	}
}

// lv78 K2 and the suspension case of the ordering guarantee: the challenge
// deadline is 10 seconds after it was minted, whatever the decision says.
func TestOnlineChallengePastItsDeadlineIsRefused(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	prepared := f.prepare(t, "mls_encrypt", request)
	f.clock.advance(proto.ChatOnlineDecisionTTLSeconds * time.Second)
	ran := false
	defer setChatOnlineAfterWorkForTesting(func() { ran = true })()
	refusedByDecision(t, f.execute("mls_encrypt", request, f.decide(t, "mls_encrypt", prepared)))
	if ran {
		t.Fatal("the action ran on a challenge past its deadline")
	}
}

// lv78 K2: a refused decision does not consume the challenge; the right
// decision for it still admits the call once, and only once.
func TestRefusedDecisionLeavesTheChallengeAndAValidOneIsSingleUse(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	prepared := f.prepare(t, "mls_encrypt", request)
	valid := f.decide(t, "mls_encrypt", prepared)
	wrong := valid
	wrong.ConversationID = "c9999999-3333-4333-8333-333333333333"
	refusedByDecision(t, f.execute("mls_encrypt", request, f.sign(t, wrong)))
	if response := f.execute("mls_encrypt", request, valid); !admitted(response) {
		t.Fatalf("the valid decision after a refused one: %+v", response)
	}
	refusedByDecision(t, f.execute("mls_encrypt", request, valid))
}

// lv78 K2: a sign-out or another sign-in between prepare and execute ends
// every challenge minted for the earlier sign-in.
func TestOnlineDecisionAfterTheBindingChangedIsRefused(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
	if _, _, err := keychain.SetAccountBinding(f.store, onlineAccount, "alice", true); err != nil {
		t.Fatal(err)
	}
	refusedByDecision(t, f.execute("mls_encrypt", request, d))
}

// lv78 K2: two executions racing on one decision yield at most one admission.
func TestConcurrentExecutionsOfOneDecisionAdmitAtMostOne(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
	const racers = 8
	start := make(chan struct{})
	results := make(chan proto.BaseResponse, racers)
	var ready sync.WaitGroup
	ready.Add(racers)
	for range racers {
		go func() {
			ready.Done()
			<-start
			results <- f.execute("mls_encrypt", request, d)
		}()
	}
	ready.Wait()
	close(start)
	count := 0
	for range racers {
		if admitted(<-results) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d of %d racing executions were admitted, want exactly 1", count, racers)
	}
}

// lv78 K3, phase (c): a deadline that passes while the action runs (the
// process was suspended after the sensitive work) withholds the output.
func TestOutputIsWithheldWhenTheDeadlinePassesDuringTheCall(t *testing.T) {
	f := newOnlineFixture(t)
	request := onlineRequest(onlineConv)
	d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
	restore := setChatOnlineAfterWorkForTesting(func() { f.clock.advance(proto.ChatOnlineDecisionTTLSeconds * time.Second) })
	defer restore()
	refusedByDecision(t, f.execute("mls_encrypt", request, d))
}
