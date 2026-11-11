//go:build !keeper_e2e

package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// lv78 review F1: the online decision trusts the pinned server keys, so no
// caller may pin one of its own. A Native Messaging frame that offers a key
// as a new active version, with no root signature to check it against,
// installs nothing in a release build, and a decision signed by that key is
// refused like any other forgery.
func TestNativeRefreshServerKeysCannotPinAKeyThatAdmitsAnOnlineDecision(t *testing.T) {
	f := newOnlineFixture(t)
	if err := keychain.SaveActiveServerKeyVersion(f.store, 1); err != nil {
		t.Fatal(err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&attacker.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := json.Marshal(map[string]any{
		"action": "refresh_server_keys", "request_id": "r-1",
		"payload": map[string]any{"keys": []map[string]any{{
			"version": 7, "status": "active",
			"public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			"issued_at":      "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z",
		}}},
	})
	if response := f.app.HandleRequest(frame); response.Success {
		t.Fatalf("a Native frame pinned an unverified server key: %+v", response)
	}
	if active, err := keychain.GetActiveServerKeyVersion(f.store); err != nil || active != 1 {
		t.Fatalf("active version = %d, %v; want 1", active, err)
	}

	request := onlineRequest(onlineConv)
	d := f.decide(t, "mls_encrypt", f.prepare(t, "mls_encrypt", request))
	d.ServerKeyVersion = 7
	f.key = attacker
	refusedByDecision(t, f.execute("mls_encrypt", request, f.sign(t, d)))
}
