// rotate_device_key_slot_test.go — rotate_device_key with
// device_wrapped_dek_b64 left empty rotates the device-wrapped DEK in
// Keeper's own personal_device_wrapped_dek slot (0.0.58).
package handlers

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func openWithStoredDeviceKey(t *testing.T, store keychain.SecretStore, wrappedB64 string) []byte {
	t.Helper()
	dkB64, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey: %v", err)
	}
	dk, _ := base64.StdEncoding.DecodeString(dkB64)
	dek, err := unwrapDeviceWrappedDEK(dk, wrappedB64)
	if err != nil {
		t.Fatalf("open with stored device key: %v", err)
	}
	return dek
}

func storedSlot(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	v, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil {
		t.Fatalf("GetPersonalDeviceWrappedDEK: %v", err)
	}
	return v
}

func assertNoLeak(t *testing.T, log *testdouble.MemoryLogger, resp proto.BaseResponse, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if log.Contains(s) {
			t.Errorf("logger echoed a wrap or key: %v", log.Messages())
		}
		if strings.Contains(resp.Error, s) {
			t.Errorf("error echoed a wrap or key: %q", resp.Error)
		}
	}
}

func TestRotateDeviceKey_EmptyInputRotatesSlot(t *testing.T) {
	deps, log, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x21)
	if resp := signupDEKForTest(deps, "pw"); !resp.Success {
		t.Fatalf("signup setup: %s", resp.Error)
	}
	oldSlot := storedSlot(t, store)
	oldDK := storedDeviceKey(t, store)
	originalDEK := openWithStoredDeviceKey(t, store, oldSlot)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{})
	if !resp.Success {
		t.Fatalf("rotate from slot: %s", resp.Error)
	}
	newWrap := resp.Data.(proto.RotateDeviceKeyResponseData).DeviceWrappedDEKB64

	newSlot := storedSlot(t, store)
	if newSlot != newWrap {
		t.Fatal("the slot must hold the rotated wrap")
	}
	if newSlot == oldSlot || storedDeviceKey(t, store) == oldDK {
		t.Fatal("device key and slot must both change")
	}
	if !bytes.Equal(openWithStoredDeviceKey(t, store, newSlot), originalDEK) {
		t.Fatal("rotation must keep the personal DEK")
	}
	assertNoLeak(t, log, resp, oldSlot, newSlot, oldDK, storedDeviceKey(t, store))

	// The personal dek_* actions keep working from the rotated slot.
	enc := HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("after rotation")),
	})
	if !enc.Success {
		t.Fatalf("encrypt from rotated slot: %s", enc.Error)
	}

	// A second rotation from the slot works too.
	if again := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{}); !again.Success {
		t.Fatalf("second rotate from slot: %s", again.Error)
	}
}

// A caller that still sends the current wrap keeps working, and the slot
// follows the rotation.
func TestRotateDeviceKey_SuppliedWrapStillWorks(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x22)
	signup := signupDEKForTest(deps, "pw")
	if !signup.Success {
		t.Fatalf("signup setup: %s", signup.Error)
	}
	current := signup.Data.(proto.DEKGenerateAndWrapDualResponseData).DeviceWrappedDEKB64

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: current})
	if !resp.Success {
		t.Fatalf("rotate with supplied wrap: %s", resp.Error)
	}
	if got := storedSlot(t, store); got != resp.Data.(proto.RotateDeviceKeyResponseData).DeviceWrappedDEKB64 {
		t.Fatal("the slot must hold the rotated wrap")
	}
}

func TestRotateDeviceKey_EmptyInputWithoutSlotIsNotFound(t *testing.T) {
	deps, log, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x23)
	dkBefore := storedDeviceKey(t, store)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("want not_found, got %+v", resp)
	}
	if storedDeviceKey(t, store) != dkBefore {
		t.Fatal("device key must stay when there is nothing to rotate")
	}
	if log.Contains("rotate_device_key successful") {
		t.Fatal("must not log success")
	}
}

func TestRotateDeviceKey_EmptyInputAfterSignoutIsNotFound(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x24)
	if resp := signupDEKForTest(deps, "pw"); !resp.Success {
		t.Fatalf("signup setup: %s", resp.Error)
	}
	if resp := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{}); !resp.Success {
		t.Fatalf("signout: %s", resp.Error)
	}
	dkBefore := storedDeviceKey(t, store)

	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("want not_found after sign-out, got %+v", resp)
	}
	if storedDeviceKey(t, store) != dkBefore {
		t.Fatal("device key must stay after a refused rotation")
	}
	if _, err := keychain.GetPersonalDeviceWrappedDEK(store); err == nil {
		t.Fatal("a refused rotation must not bring the signed-out slot back")
	}
}

// A slot value that does not open is Keeper's own state gone bad:
// storage_failure, nothing changes, and the stored value is not echoed.
func TestRotateDeviceKey_CorruptSlotIsStorageFailure(t *testing.T) {
	undecryptable := make([]byte, 12+32+16)
	for i := range undecryptable {
		undecryptable[i] = byte(0x80 + i)
	}
	cases := map[string]string{
		"not_base64":    "SLOT_SENTINEL_NOT_BASE64!!",
		"too_short":     base64.StdEncoding.EncodeToString([]byte("SLOT_SENTINEL_SHORT")),
		"undecryptable": base64.StdEncoding.EncodeToString(undecryptable),
	}
	for name, slot := range cases {
		t.Run(name, func(t *testing.T) {
			deps, log, store := newTestDeps(t)
			seedKeychainDeviceKeyForRotate(t, store, 0x25)
			if err := keychain.SavePersonalDeviceWrappedDEK(store, slot); err != nil {
				t.Fatalf("seed slot: %v", err)
			}
			dkBefore := storedDeviceKey(t, store)

			resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{})
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
				t.Fatalf("want storage_failure, got %+v", resp)
			}
			if storedDeviceKey(t, store) != dkBefore || storedSlot(t, store) != slot {
				t.Fatal("a refused rotation must leave the device key and the slot alone")
			}
			assertNoLeak(t, log, resp, slot, "SLOT_SENTINEL", dkBefore)
		})
	}
}

// The same bad bytes sent by the caller stay a request error.
func TestRotateDeviceKey_BadSuppliedWrapKeepsRequestErrorCodes(t *testing.T) {
	deps, log, store := newTestDeps(t)
	seedKeychainDeviceKeyForRotate(t, store, 0x26)
	if resp := signupDEKForTest(deps, "pw"); !resp.Success {
		t.Fatalf("signup setup: %s", resp.Error)
	}
	short := base64.StdEncoding.EncodeToString([]byte("SUPPLIED_SENTINEL"))
	if resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: short}); resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("short supplied wrap: want validation_error, got %+v", resp)
	}
	bogus := base64.StdEncoding.EncodeToString(make([]byte, 60))
	resp := HandleRotateDeviceKey(deps, proto.RotateDeviceKeyRequest{DeviceWrappedDEKB64: bogus})
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("undecryptable supplied wrap: want crypto_failure, got %+v", resp)
	}
	assertNoLeak(t, log, resp, short, bogus, "SUPPLIED_SENTINEL")
}
