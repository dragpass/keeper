package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/dragpass/keeper/config"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// handoverWorld is an old device that can really sign a handover: an account
// key that signs the new device's declaration, and an active leaf L1.
type handoverWorld struct {
	*onlineFixture
	oldFP   string
	request json.RawMessage
	call    accountCall
}

// seedActiveLeaf stores a fresh active leaf for this account and device and
// returns its fingerprint.
func seedActiveLeaf(t *testing.T, store keychain.SecretStore, account, device string) string {
	t.Helper()
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveMLSLeafKey(store, keychain.MLSLeafKey{
		AccountID: account, DeviceID: device, SecretKey: secret, PublicKey: public, Declaration: []byte("declaration"),
	}); err != nil {
		t.Fatal(err)
	}
	fp, err := keepercrypto.MLSLeafSignatureKeyFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func newHandoverWorld(t *testing.T) *handoverWorld {
	t.Helper()
	f := newOnlineFixture(t)
	_, privatePEM := setupAppKeyPair(t, f.app)
	accountKey, err := keepercrypto.ParsePrivateKey(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	oldFP := seedActiveLeaf(t, f.store, onlineAccount, onlineDevice)
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newFP, _ := keepercrypto.MLSLeafSignatureKeyFingerprint(newPublic)
	now := f.clock.Now().Unix()
	decl := proto.MLSLeafDeclaration{
		AccountID: onlineAccount, DeviceID: accountOnlineOtherDevice,
		SignatureKey: base64.StdEncoding.EncodeToString(newPublic), SignatureKeyFingerprint: newFP,
		NotBefore: now, NotAfter: now + 86400, Reason: proto.MLSLeafReasonRotate,
	}
	sig, err := keepercrypto.SignData(accountKey, decl.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	decl.Signature = base64.StdEncoding.EncodeToString(sig)
	expiresAt := now + 300
	request := rawJSON(map[string]any{
		"account_id": onlineAccount, "new_declaration": decl, "expires_at": expiresAt,
		"old_signature_key_fingerprint": oldFP,
	})
	return &handoverWorld{onlineFixture: f, oldFP: oldFP, request: request, call: accountCall{
		action: proto.ActionMLSLeafHandoverSign, request: request, takeover: accountOnlineTakeover,
		// Spelled out rather than built, so the test pins the wire string the API
		// derives from its stored takeover request.
		target: "takeover:" + accountOnlineTakeover + "/old_fp:" + oldFP + "/new_device:" + accountOnlineOtherDevice +
			"/new_fp:" + newFP + "/expires_at:" + strconv.FormatInt(expiresAt, 10),
	}}
}

// lv78 old leaf binding: the handover decision names the old device's active
// leaf, the one that signs. A leaf replaced within the same sign-in between
// the decision and its execution would sign with a leaf the person never
// approved for; the held decision must not admit that.
func TestHandoverDecisionIsBoundToTheActiveLeafThatSigns(t *testing.T) {
	t.Run("the decision admits a handover signed by the bound leaf", func(t *testing.T) {
		w := newHandoverWorld(t)
		prepared := w.prepareAccount(t, w.call)
		if prepared.Target != w.call.target {
			t.Fatalf("prepared target\n got %s\nwant %s", prepared.Target, w.call.target)
		}
		response := w.executeAccount(w.call, w.request, w.decideAccount(t, w.call, prepared))
		data, ok := response.Data.(proto.MLSLeafHandoverSignResponseData)
		if !response.Success || !ok || data.Handover.OldSignatureKeyFP != w.oldFP {
			t.Fatalf("a handover by the bound leaf was not signed by it: %+v", response)
		}
	})
	t.Run("a leaf replaced after the decision is refused before it signs", func(t *testing.T) {
		w := newHandoverWorld(t)
		prepared := w.prepareAccount(t, w.call)
		// The API answers for the target Keeper prepared.
		issued := w.call
		issued.target = prepared.Target
		d := w.decideAccount(t, issued, prepared)
		replacement := seedActiveLeaf(t, w.store, onlineAccount, onlineDevice)
		ran, response := accountRan(func() proto.BaseResponse { return w.executeAccount(w.call, w.request, d) })
		if data, ok := response.Data.(proto.MLSLeafHandoverSignResponseData); ok && response.Success {
			t.Fatalf("the held decision signed a handover with the replacement leaf (old_fp is the replacement: %t)",
				data.Handover.OldSignatureKeyFP == replacement)
		}
		refusedByDecision(t, response)
		if ran {
			t.Fatal("the handover ran after the bound leaf was replaced")
		}
		if _, still := w.app.accountOnline.peek(d.Challenge, w.clock.Now()); !still {
			t.Fatal("a refused execution consumed the challenge")
		}
	})
	t.Run("prepare refuses when the active leaf is another account's", func(t *testing.T) {
		w := newHandoverWorld(t)
		record, found, err := keychain.GetMLSLeafKey(w.store)
		if err != nil || !found {
			t.Fatal(err)
		}
		record.AccountID = accountOnlineRemoved
		if err := keychain.SaveMLSLeafKey(w.store, record); err != nil {
			t.Fatal(err)
		}
		response := w.app.PrepareMLSAccountOnline("", proto.MLSAccountOnlinePrepareRequest{
			Action: w.call.action, Request: w.request, TokenID: onlineToken,
			SessionIssuedAtNanos: onlineSession, TakeoverRequestID: w.call.takeover,
		})
		if response.Success || response.ErrorCode != ErrCodeChatOnlineDecisionRefused {
			t.Fatalf("prepare over another account's leaf: %+v", response)
		}
	})
	t.Run("prepare refuses a request naming another leaf than the active one", func(t *testing.T) {
		w := newHandoverWorld(t)
		seedActiveLeaf(t, w.store, onlineAccount, onlineDevice)
		response := w.app.PrepareMLSAccountOnline("", proto.MLSAccountOnlinePrepareRequest{
			Action: w.call.action, Request: w.request, TokenID: onlineToken,
			SessionIssuedAtNanos: onlineSession, TakeoverRequestID: w.call.takeover,
		})
		if response.Success || response.ErrorCode != ErrCodeChatOnlineDecisionRefused {
			t.Fatalf("prepare for a leaf that is not active: %+v", response)
		}
	})
}

// lv78 old leaf binding: a held handover decision does not outlive the
// sign-in it was prepared under (another sign-in, a sign-out, a device reset).
func TestHandoverDecisionAfterTheSignInChangedIsRefused(t *testing.T) {
	for name, change := range map[string]func(*handoverWorld) error{
		"signed in again": func(w *handoverWorld) error {
			_, _, err := keychain.SetAccountBinding(w.store, onlineAccount, "alice", true)
			return err
		},
		"signed out": func(w *handoverWorld) error {
			_, _, err := keychain.SignOutAccountBinding(w.store)
			return err
		},
		"device reset": func(w *handoverWorld) error {
			return w.store.Set(config.Service, config.DeviceID, "d9999999-4444-4444-8444-444444444444")
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newHandoverWorld(t)
			prepared := w.prepareAccount(t, w.call)
			issued := w.call
			issued.target = prepared.Target
			d := w.decideAccount(t, issued, prepared)
			if err := change(w); err != nil {
				t.Fatal(err)
			}
			refusedBeforeTheAccountAction(t, func() proto.BaseResponse { return w.executeAccount(w.call, w.request, d) })
		})
	}
}

// The API pins the same vector (ariadne
// internal/services/account/mls_online_decision_canonical_test.go
// TestMLSHandoverOnlineTarget_Golden); both must change together or no
// handover decision matches.
func TestMLSHandoverOnlineTargetMatchesTheAPIGoldenVector(t *testing.T) {
	got := MLSHandoverOnlineTarget("f9999999-6666-4666-8666-666666666666",
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "d7777777-4444-4444-8444-444444444444",
		"abababababababababababababababababababababababababababababababab", 1900000000)
	want := "takeover:f9999999-6666-4666-8666-666666666666" +
		"/old_fp:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
		"/new_device:d7777777-4444-4444-8444-444444444444" +
		"/new_fp:abababababababababababababababababababababababababababababababab/expires_at:1900000000"
	if got != want {
		t.Fatalf("handover target\n got %s\nwant %s", got, want)
	}
	if len(want) > proto.MLSAccountOnlineTargetMaxLen {
		t.Fatalf("the handover target (%d bytes) exceeds the decision's target bound", len(want))
	}
}
