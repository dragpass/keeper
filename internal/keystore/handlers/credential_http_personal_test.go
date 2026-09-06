package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestWithCredentialDEKUsesLocalPersonalWrap(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(i + 1)
	}
	setKeychainDeviceKey(t, store, deviceKey)

	dual := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{Password: "password"})
	if !dual.Success {
		t.Fatalf("generate personal DEK: %s", dual.Error)
	}

	called := false
	err := withCredentialDEK(deps, credentialKeySource{useLocalPersonalDEK: true}, func(dek []byte) error {
		called = len(dek) == 32
		return nil
	})
	if err != nil || !called {
		t.Fatalf("withCredentialDEK called = %v, err = %v", called, err)
	}

	if _, err := keychain.GetPersonalDeviceWrappedDEK(store); err != nil {
		t.Fatalf("personal DEK missing after use: %v", err)
	}
}

func TestWithCredentialDEKFailsWithoutLocalPersonalWrap(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, make([]byte, 32))

	err := withCredentialDEK(deps, credentialKeySource{useLocalPersonalDEK: true}, func([]byte) error {
		t.Fatal("callback must not run without a local personal DEK")
		return nil
	})
	if err == nil {
		t.Fatal("missing local personal DEK accepted")
	}
}
