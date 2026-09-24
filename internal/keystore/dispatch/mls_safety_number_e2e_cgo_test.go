//go:build mls && cgo

// The pairwise safety number (design §0.3 policy 3, Q10 (a)): both sides
// compute the same 60 digits and QR bytes from the two accounts and their
// account key fingerprints, and a verify that carries the compared value is
// settled only when the Keeper recomputes the same value from its own key and
// the peer key it is handed.

package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

type safetyNumber struct {
	SafetyNumber    string `json:"safety_number"`
	SafetyNumberB64 string `json:"safety_number_b64"`
	OwnFingerprint  string `json:"own_fingerprint"`
	PeerFingerprint string `json:"peer_fingerprint"`
}

func (k *keeper) safetyNumberFor(peer *keeper) safetyNumber {
	k.t.Helper()
	pem, err := keychain.GetPublicKey(peer.store)
	if err != nil {
		k.t.Fatal(err)
	}
	resp := k.must("peer_key_safety_number", map[string]string{
		"owner_account_id": k.id, "account_id": peer.id, "public_key": pem,
	})
	raw, err := json.Marshal(resp.Data)
	if err != nil {
		k.t.Fatal(err)
	}
	var out safetyNumber
	if err := json.Unmarshal(raw, &out); err != nil {
		k.t.Fatal(err)
	}
	return out
}

func (k *keeper) verifyWithSafetyNumber(peer *keeper, safetyB64 string) (ok bool, code string) {
	k.t.Helper()
	pem, err := keychain.GetPublicKey(peer.store)
	if err != nil {
		k.t.Fatal(err)
	}
	resp := k.call("peer_key_pin_verify", map[string]string{
		"owner_account_id": k.id, "account_id": peer.id,
		"fingerprint": crypto.AccountKeyFingerprint([]byte(pem)), "public_key": pem,
		"safety_number_b64": safetyB64,
	})
	return resp.Success, string(resp.ErrorCode)
}

// Q10's repro. Alice and Bob each ask their own Keeper for the number of the
// pair and get the same one; a verify carrying the number Alice compared is
// settled, and one carrying any other number is refused with the pin
// untouched.
func TestMLSSafetyNumber_BothSidesSeeOneNumberAndVerifyChecksIt(t *testing.T) {
	c := newDM(t)
	fromAlice := c.alice.safetyNumberFor(c.bob)
	fromBob := c.bob.safetyNumberFor(c.alice)
	if fromAlice.SafetyNumber == "" || fromAlice.SafetyNumber != fromBob.SafetyNumber ||
		fromAlice.SafetyNumberB64 != fromBob.SafetyNumberB64 || len(fromAlice.SafetyNumber) != 60 {
		t.Fatalf("alice sees %+v, bob sees %+v", fromAlice, fromBob)
	}
	if fromAlice.OwnFingerprint != fromBob.PeerFingerprint || fromAlice.PeerFingerprint != fromBob.OwnFingerprint {
		t.Fatalf("fingerprints do not cross: %+v / %+v", fromAlice, fromBob)
	}

	// A number for another pair: Carol's with Bob.
	carol := newKeeper(t, e2eCarol)
	other := carol.safetyNumberFor(c.bob)
	if ok, code := c.alice.verifyWithSafetyNumber(c.bob, other.SafetyNumberB64); ok || code != "crypto_failure" {
		t.Fatalf("verify with another pair's number = %v %q; want crypto_failure", ok, code)
	}
	if _, err := keychain.GetPeerKeyPin(c.alice.store, c.alice.id, c.bob.id); err == nil {
		if pin, _ := keychain.GetPeerKeyPin(c.alice.store, c.alice.id, c.bob.id); pin.State == keychain.PeerKeyPinStateVerified {
			t.Fatal("a refused verify left bob verified")
		}
	}
	if ok, code := c.alice.verifyWithSafetyNumber(c.bob, fromAlice.SafetyNumberB64); !ok {
		t.Fatalf("verify with the compared number = %q", code)
	}
	if pin, err := keychain.GetPeerKeyPin(c.alice.store, c.alice.id, c.bob.id); err != nil || pin.State != keychain.PeerKeyPinStateVerified {
		t.Fatalf("bob's pin after the verify = %+v, %v", pin, err)
	}
}
