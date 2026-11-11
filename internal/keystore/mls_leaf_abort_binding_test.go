package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/config"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// leafBindingWorld is an App session holding the chat lease on a Keeper
// signed in as onlineAccount, with an account key that signs declarations.
type leafBindingWorld struct {
	*onlineFixture
	publicPEM  string
	privatePEM string
}

func newLeafBindingWorld(t *testing.T) *leafBindingWorld {
	t.Helper()
	f := newOnlineFixture(t)
	publicPEM, privatePEM := setupAppKeyPair(t, f.app)
	return &leafBindingWorld{onlineFixture: f, publicPEM: publicPEM, privatePEM: privatePEM}
}

// leafRecord mints a leaf key with a declaration the account key signed.
func (w *leafBindingWorld) leafRecord(t *testing.T, account, device string) (keychain.MLSLeafKey, string) {
	t.Helper()
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := keepercrypto.MLSLeafSignatureKeyFingerprint(public)
	now := w.clock.Now().Unix()
	decl := proto.MLSLeafDeclaration{
		AccountID: account, DeviceID: device, SignatureKey: base64.StdEncoding.EncodeToString(public),
		SignatureKeyFingerprint: fp, NotBefore: now, NotAfter: now + 86400, Reason: proto.MLSLeafReasonRotate,
	}
	priv, err := keepercrypto.ParsePrivateKey(w.privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keepercrypto.SignData(priv, decl.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	decl.Signature = base64.StdEncoding.EncodeToString(sig)
	ext, err := proto.EncodeMLSLeafExtension(decl, w.publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	return keychain.MLSLeafKey{AccountID: account, DeviceID: device, SecretKey: secret, PublicKey: public, Declaration: ext}, fp
}

func (w *leafBindingWorld) seedPending(t *testing.T, account, device string) string {
	t.Helper()
	record, fp := w.leafRecord(t, account, device)
	if err := keychain.SaveMLSLeafPending(w.store, record); err != nil {
		t.Fatal(err)
	}
	return fp
}

func (w *leafBindingWorld) seedActive(t *testing.T, account, device string) string {
	t.Helper()
	record, fp := w.leafRecord(t, account, device)
	if err := keychain.SaveMLSLeafKey(w.store, record); err != nil {
		t.Fatal(err)
	}
	return fp
}

// slot is the raw record in an MLS leaf slot, "" when empty.
func (w *leafBindingWorld) slot(t *testing.T, name string) string {
	t.Helper()
	raw, err := w.store.Get(config.Service, name)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal(err)
	}
	return raw
}

func (w *leafBindingWorld) bindingGeneration(t *testing.T) uint64 {
	t.Helper()
	binding, found, err := keychain.GetAccountBinding(w.store)
	if err != nil || !found {
		t.Fatalf("binding: found=%v err=%v", found, err)
	}
	return binding.Generation
}

func (w *leafBindingWorld) call(t *testing.T, action string, payload map[string]any) proto.BaseResponse {
	t.Helper()
	frame, err := json.Marshal(map[string]any{"action": action, "request_id": "r-1", "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	return w.app.HandleAppFencedRequest(sessionA, w.epoch, "", true, frame)
}

func (w *leafBindingWorld) abort(t *testing.T, account string, generation uint64, pendingFP string) proto.BaseResponse {
	t.Helper()
	return w.call(t, proto.ActionMLSLeafAbort, map[string]any{
		"account_id": account, "binding_generation": generation, "pending_signature_key_fingerprint": pendingFP,
	})
}

// lv78: mls_leaf_abort deletes only the pending leaf the caller names, for
// the account binding it names, and only while that binding is current.
func TestMLSLeafAbortDeletesOnlyTheNamedPendingOfTheCurrentBinding(t *testing.T) {
	t.Run("the named pending of the current binding is deleted", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		w.seedActive(t, onlineAccount, onlineDevice)
		activeRaw := w.slot(t, config.MLSLeafSignatureKey)
		fp := w.seedPending(t, onlineAccount, onlineDevice)
		response := w.abort(t, onlineAccount, w.bindingGeneration(t), fp)
		data, ok := response.Data.(proto.MLSLeafAbortResponseData)
		if !response.Success || !ok || !data.Aborted {
			t.Fatalf("abort of the named pending: %+v", response)
		}
		if w.slot(t, config.MLSLeafSignatureKeyPending) != "" || w.slot(t, config.MLSLeafSignatureKey) != activeRaw {
			t.Fatal("abort left the pending entry or touched the active one")
		}
	})

	refusedAndKept := func(t *testing.T, w *leafBindingWorld, response proto.BaseResponse, pendingRaw, activeRaw string) {
		t.Helper()
		if response.Success {
			t.Fatalf("abort was not refused: %+v", response)
		}
		if w.slot(t, config.MLSLeafSignatureKeyPending) != pendingRaw || w.slot(t, config.MLSLeafSignatureKey) != activeRaw {
			t.Fatal("a refused abort changed a leaf slot")
		}
	}

	t.Run("a stale App after a sign-out is refused", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, onlineAccount, onlineDevice)
		generation := w.bindingGeneration(t)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		if _, _, err := keychain.SignOutAccountBinding(w.store); err != nil {
			t.Fatal(err)
		}
		refusedAndKept(t, w, w.abort(t, onlineAccount, generation, fp), pendingRaw, "")
	})
	t.Run("a stale App after another sign-in of the same account is refused", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, onlineAccount, onlineDevice)
		generation := w.bindingGeneration(t)
		if _, _, err := keychain.SetAccountBinding(w.store, onlineAccount, "alice", true); err != nil {
			t.Fatal(err)
		}
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		refusedAndKept(t, w, w.abort(t, onlineAccount, generation, fp), pendingRaw, "")
	})
	t.Run("a stale App after a new chat sign-in is refused by the gate", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, onlineAccount, onlineDevice)
		generation := w.bindingGeneration(t)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		if r := w.app.PrepareChatLogin("intent-2", "", 0); !r.Success {
			t.Fatalf("prepare chat login: %+v", r)
		}
		if r := w.app.CommitChatLogin("intent-2", onlineAccount, "alice"); !r.Success {
			t.Fatalf("commit chat login: %+v", r)
		}
		response := w.abort(t, onlineAccount, generation, fp)
		if response.ErrorCode != ErrCodeChatRuntimeRevoked && response.ErrorCode != ChatSessionRequired {
			t.Fatalf("a stale App's abort after a new chat sign-in: %+v", response)
		}
		refusedAndKept(t, w, response, pendingRaw, "")
	})
	t.Run("another account is refused", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, onlineAccount, onlineDevice)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		refusedAndKept(t, w, w.abort(t, accountOnlineRemoved, w.bindingGeneration(t), fp), pendingRaw, "")
	})
	t.Run("a pending entry of another account is not deleted", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, accountOnlineRemoved, onlineDevice)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		refusedAndKept(t, w, w.abort(t, onlineAccount, w.bindingGeneration(t), fp), pendingRaw, "")
	})
	t.Run("a pending entry of another device is not deleted", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		fp := w.seedPending(t, onlineAccount, accountOnlineOtherDevice)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		refusedAndKept(t, w, w.abort(t, onlineAccount, w.bindingGeneration(t), fp), pendingRaw, "")
	})
	t.Run("a newer pending of the same sign-in is not deleted by an abort naming the older", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		older := w.seedPending(t, onlineAccount, onlineDevice)
		// Another tab aborts the older entry and declares again before this
		// abort, decided on the older status, lands.
		w.seedPending(t, onlineAccount, onlineDevice)
		pendingRaw := w.slot(t, config.MLSLeafSignatureKeyPending)
		refusedAndKept(t, w, w.abort(t, onlineAccount, w.bindingGeneration(t), older), pendingRaw, "")
	})
	t.Run("an abort after the named leaf was promoted is refused and the active leaf stays", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		record, fp := w.leafRecord(t, onlineAccount, onlineDevice)
		if err := keychain.SaveMLSLeafKey(w.store, record); err != nil {
			t.Fatal(err)
		}
		activeRaw := w.slot(t, config.MLSLeafSignatureKey)
		refusedAndKept(t, w, w.abort(t, onlineAccount, w.bindingGeneration(t), fp), "", activeRaw)
	})
	t.Run("an abort after the active leaf was replaced is refused and the active leaf stays", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		named := w.seedPending(t, onlineAccount, onlineDevice)
		if err := keychain.SaveMLSLeafKey(w.store, mustPending(t, w)); err != nil {
			t.Fatal(err)
		}
		if _, err := keychain.DeleteMLSLeafPending(w.store); err != nil {
			t.Fatal(err)
		}
		w.seedActive(t, onlineAccount, onlineDevice)
		activeRaw := w.slot(t, config.MLSLeafSignatureKey)
		refusedAndKept(t, w, w.abort(t, onlineAccount, w.bindingGeneration(t), named), "", activeRaw)
	})
}

func mustPending(t *testing.T, w *leafBindingWorld) keychain.MLSLeafKey {
	t.Helper()
	record, found, err := keychain.GetMLSLeafPending(w.store)
	if err != nil || !found {
		t.Fatalf("pending: found=%v err=%v", found, err)
	}
	return record
}

// lv78: mls_leaf_status answers only for the current binding of the account
// the caller names, and names that binding so an abort can be bound to it.
func TestMLSLeafStatusIsBoundToTheCurrentBinding(t *testing.T) {
	t.Run("it names the binding and this account's leaves", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		active := w.seedActive(t, onlineAccount, onlineDevice)
		pending := w.seedPending(t, onlineAccount, onlineDevice)
		response := w.call(t, proto.ActionMLSLeafStatus, map[string]any{"account_id": onlineAccount})
		raw, _ := json.Marshal(response.Data)
		var data map[string]any
		_ = json.Unmarshal(raw, &data)
		if !response.Success || data["account_id"] != onlineAccount || data["binding_generation"] != float64(w.bindingGeneration(t)) ||
			data["active_signature_key_fingerprint"] != active || data["pending_signature_key_fingerprint"] != pending {
			t.Fatalf("status: %+v", response)
		}
	})
	for name, setup := range map[string]func(*testing.T, *leafBindingWorld) string{
		"after a sign-out": func(t *testing.T, w *leafBindingWorld) string {
			if _, _, err := keychain.SignOutAccountBinding(w.store); err != nil {
				t.Fatal(err)
			}
			return onlineAccount
		},
		"for another account": func(t *testing.T, w *leafBindingWorld) string { return accountOnlineRemoved },
	} {
		t.Run("it is refused "+name, func(t *testing.T) {
			w := newLeafBindingWorld(t)
			w.seedActive(t, onlineAccount, onlineDevice)
			account := setup(t, w)
			response := w.call(t, proto.ActionMLSLeafStatus, map[string]any{"account_id": account})
			if response.Success || response.Data != nil {
				t.Fatalf("status was answered: %+v", response)
			}
		})
	}
	t.Run("it does not report another account's leaf records", func(t *testing.T) {
		w := newLeafBindingWorld(t)
		w.seedActive(t, accountOnlineRemoved, onlineDevice)
		w.seedPending(t, accountOnlineRemoved, onlineDevice)
		response := w.call(t, proto.ActionMLSLeafStatus, map[string]any{"account_id": onlineAccount})
		raw, _ := json.Marshal(response.Data)
		var data map[string]any
		_ = json.Unmarshal(raw, &data)
		if response.Success && (data["has_active"] != false || data["has_pending"] != false) {
			t.Fatalf("status reported another account's leaf: %s", raw)
		}
	})
}
