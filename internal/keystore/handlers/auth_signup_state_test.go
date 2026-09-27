package handlers

import (
	"bytes"
	"maps"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const signupRecoveryKey = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"

func signupRequest() proto.AuthSignupPrepareRequest {
	return proto.AuthSignupPrepareRequest{Alias: "alice", Password: "correct horse battery staple", RecoveryKey: signupRecoveryKey}
}

// seedRegisteredDevice gives the store what a signed-up device holds: an
// identity keypair, a session code and a device-wrapped personal DEK.
func seedRegisteredDevice(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x66}, 32))
	pair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, save := range []error{
		keychain.SavePrivateKey(store, pair.PrivateKey),
		keychain.SavePublicKey(store, pair.PublicKey),
		keychain.SaveSessionCode(store, "existing-session-code"),
		keychain.SavePersonalDeviceWrappedDEK(store, "existing-device-wrapped-dek"),
	} {
		if save != nil {
			t.Fatal(save)
		}
	}
}

// A signup on a registered device is refused. The refusal must not have
// replaced the personal DEK the device's existing data is wrapped under.
func TestAuthSignupPrepareRefusedOnARegisteredDeviceChangesNothing(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedRegisteredDevice(t, store)
	before := store.Snapshot()

	response := HandleAuthSignupPrepare(deps, signupRequest())
	if response.Success {
		t.Fatal("signup on a registered device was accepted")
	}
	if after := store.Snapshot(); !maps.Equal(before, after) {
		t.Fatalf("a refused signup changed the keyring:\nbefore=%v\nafter=%v", keysOf(before), keysOf(after))
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
