// storage_test.go — unit tests that call the keychain package directly.
//
// **Defects this test catches:**
//   - Round-trip regressions for SaveX/GetX pairs
//   - GetX failing to return a sentinel error after DeleteX
//   - keyring backend (zalando/go-keyring) dependency regressions
//
// This file verifies round-trips on KeyringSecretStore (production path).
// Unit tests over MemorySecretStore live separately in store_test.go.
//
// **Previous location:** internal/keystore/storage_test.go.
package keychain

import (
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	m.Run()
}

func TestPrivateKeyOperations(t *testing.T) {
	store := defaultKeyringStore()
	expectedKey := "mock-private-key-12345"

	if err := SavePrivateKey(store, expectedKey); err != nil {
		t.Fatalf("Failed to save private key: %v", err)
	}

	got, err := GetPrivateKey(store)
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}

	if got != expectedKey {
		t.Errorf("Private key mismatch.\nGot: %s\nWant: %s", got, expectedKey)
	}
}

func TestPublicKeyOperations(t *testing.T) {
	store := defaultKeyringStore()
	expectedKey := "mock-public-key-67890"

	if err := SavePublicKey(store, expectedKey); err != nil {
		t.Fatalf("Failed to save public key: %v", err)
	}

	got, err := GetPublicKey(store)
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	if got != expectedKey {
		t.Errorf("Public key mismatch.\nGot: %s\nWant: %s", got, expectedKey)
	}
}

func TestServerPublicKeyOperations(t *testing.T) {
	store := defaultKeyringStore()
	expectedKey := "mock-server-public-key-abcde"

	if err := SaveServerPublicKey(store, expectedKey); err != nil {
		t.Fatalf("Failed to save server public key: %v", err)
	}

	got, err := GetServerPublicKey(store)
	if err != nil {
		t.Fatalf("Failed to get server public key: %v", err)
	}

	if got != expectedKey {
		t.Errorf("Server public key mismatch.\nGot: %s\nWant: %s", got, expectedKey)
	}
}

func TestDeviceKeyOperations(t *testing.T) {
	store := defaultKeyringStore()
	expectedKey := "mock-device-key-secret"

	if err := SaveDeviceKey(store, expectedKey); err != nil {
		t.Fatalf("Failed to save device key: %v", err)
	}

	got, err := GetDeviceKey(store)
	if err != nil {
		t.Fatalf("Failed to get device key: %v", err)
	}
	if got != expectedKey {
		t.Errorf("Device key mismatch.\nGot: %s\nWant: %s", got, expectedKey)
	}

	if err := DeleteDeviceKey(store); err != nil {
		t.Fatalf("Failed to delete device key: %v", err)
	}

	_, err = GetDeviceKey(store)
	if err == nil {
		t.Error("Expected error after deleting device key, but got nil")
	}
}

func TestSessionCodeOperations(t *testing.T) {
	store := defaultKeyringStore()
	expectedCode := "mock-session-code-xyz"

	if err := SaveSessionCode(store, expectedCode); err != nil {
		t.Fatalf("Failed to save session code: %v", err)
	}

	got, err := GetSessionCode(store)
	if err != nil {
		t.Fatalf("Failed to get session code: %v", err)
	}
	if got != expectedCode {
		t.Errorf("Session code mismatch.\nGot: %s\nWant: %s", got, expectedCode)
	}

	if err := DeleteSessionCode(store); err != nil {
		t.Fatalf("Failed to delete session code: %v", err)
	}

	_, err = GetSessionCode(store)
	if err == nil {
		t.Error("Expected error after deleting session code, but got nil")
	}
}

// defaultKeyringStore returns a KeyringSecretStore wired to the mocked keyring
// backend (set up by TestMain). Production callers use this same store via
// keystore.DefaultApp().Store; tests bypass the *App layer to call keychain
// helpers directly.
func defaultKeyringStore() SecretStore {
	return KeyringSecretStore{}
}
