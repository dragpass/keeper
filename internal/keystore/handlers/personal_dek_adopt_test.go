// personal_dek_adopt_test.go — personal_dek_adopt stores the Extension's old
// device master copy only into an empty slot on a device that is not signed
// out, only when it opens with the stored device key, and never echoes or
// logs the wrap or the key.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// adoptFixture seeds a device key and returns a wrap of a fresh DEK under it,
// with the slot left empty, as on a device whose only copy is the Extension's.
func adoptFixture(t *testing.T) (Deps, *testdouble.MemoryLogger, []byte, string) {
	t.Helper()
	deps, log, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x60 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(0x90 + i)
	}
	wrapped, err := aesGCMSeal(deviceKey, dek)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return deps, log, deviceKey, wrapped
}

func adopt(d Deps, wrapped string) proto.BaseResponse {
	return HandlePersonalDEKAdopt(d, proto.PersonalDEKAdoptRequest{DeviceWrappedDEKB64: wrapped})
}

func adoptData(t *testing.T, resp proto.BaseResponse) proto.PersonalDEKAdoptResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("adopt failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	return resp.Data.(proto.PersonalDEKAdoptResponseData)
}

func slotOf(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	value, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil {
		return ""
	}
	return value
}

func TestPersonalDEKAdopt_EmptySlotIsAdoptedAndUsable(t *testing.T) {
	deps, _, _, wrapped := adoptFixture(t)
	if data := adoptData(t, adopt(deps, wrapped)); !data.Adopted || data.Reason != "" {
		t.Fatalf("data = %+v", data)
	}
	if got := slotOf(t, deps.Store); got != wrapped {
		t.Fatal("the slot does not hold the adopted wrap")
	}
	enc := HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if !enc.Success {
		t.Fatalf("encrypt from the adopted slot: %s", enc.Error)
	}
}

func TestPersonalDEKAdopt_SignedOutIsNotAdopted(t *testing.T) {
	deps, _, _, wrapped := adoptFixture(t)
	if resp := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{}); !resp.Success {
		t.Fatalf("signout: %s", resp.Error)
	}
	data := adoptData(t, adopt(deps, wrapped))
	if data.Adopted || data.Reason != proto.PersonalDEKAdoptReasonSignedOut {
		t.Fatalf("data = %+v", data)
	}
	if got := slotOf(t, deps.Store); got != "" {
		t.Fatal("a signed-out device got its device master back")
	}
}

func TestPersonalDEKAdopt_OccupiedSlotIsKept(t *testing.T) {
	deps, _, deviceKey, wrapped := adoptFixture(t)
	fresh, err := aesGCMSeal(deviceKey, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePersonalDeviceWrappedDEK(deps.Store, fresh); err != nil {
		t.Fatal(err)
	}
	data := adoptData(t, adopt(deps, wrapped))
	if data.Adopted || data.Reason != proto.PersonalDEKAdoptReasonSlotOccupied {
		t.Fatalf("data = %+v", data)
	}
	if got := slotOf(t, deps.Store); got != fresh {
		t.Fatal("the slot was overwritten")
	}
}

func TestPersonalDEKAdopt_WrapUnderAnotherDeviceKeyIsCryptoFailure(t *testing.T) {
	deps, _, _, _ := adoptFixture(t)
	other, err := aesGCMSeal(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	resp := adopt(deps, other)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("want crypto_failure, got %+v", resp)
	}
	if got := slotOf(t, deps.Store); got != "" {
		t.Fatal("a wrap that does not open was stored")
	}
}

func TestPersonalDEKAdopt_NoDeviceKeyIsNotFound(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	wrapped, err := aesGCMSeal(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	resp := adopt(deps, wrapped)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("want not_found, got %+v", resp)
	}
}

func TestPersonalDEKAdopt_Validation(t *testing.T) {
	deps, _, _, wrapped := adoptFixture(t)
	raw, _ := base64.StdEncoding.DecodeString(wrapped)
	cases := map[string]string{
		"empty":    "",
		"not b64":  "%%%",
		"url-safe": base64.RawURLEncoding.EncodeToString(raw),
		"short":    base64.StdEncoding.EncodeToString(raw[:59]),
		"long":     base64.StdEncoding.EncodeToString(append(append([]byte{}, raw...), 0)),
	}
	for name, value := range cases {
		resp := adopt(deps, value)
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Errorf("%s: want validation_error, got %+v", name, resp)
		}
	}
	if got := slotOf(t, deps.Store); got != "" {
		t.Fatal("an invalid request wrote the slot")
	}
}

func TestPersonalDEKAdopt_NoWrapOrKeyInResponsesOrLogs(t *testing.T) {
	deps, log, deviceKey, wrapped := adoptFixture(t)
	deviceKeyB64 := base64.StdEncoding.EncodeToString(deviceKey)
	other, _ := aesGCMSeal(make([]byte, 32), make([]byte, 32))

	responses := []proto.BaseResponse{adopt(deps, other), adopt(deps, wrapped), adopt(deps, wrapped)}
	HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	responses = append(responses, adopt(deps, wrapped))

	for i, resp := range responses {
		encoded, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{wrapped, other, deviceKeyB64} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("response %d echoes the wrap or the device key", i)
			}
		}
	}
	for _, line := range log.Messages() {
		for _, secret := range []string{wrapped, other, deviceKeyB64} {
			if strings.Contains(line, secret) {
				t.Errorf("log line carries the wrap or the device key: %q", line)
			}
		}
	}
}

// A sign-out racing an adoption must leave the device signed out with no
// device master, whichever runs first.
func TestPersonalDEKAdopt_RacingSignoutNeverRestoresTheDeviceMaster(t *testing.T) {
	for i := 0; i < 50; i++ {
		deps, _, _, wrapped := adoptFixture(t)
		var (
			start sync.WaitGroup
			done  sync.WaitGroup
		)
		start.Add(1)
		done.Add(2)
		var adoptResp proto.BaseResponse
		go func() {
			defer done.Done()
			start.Wait()
			adoptResp = adopt(deps, wrapped)
		}()
		go func() {
			defer done.Done()
			start.Wait()
			HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
		}()
		start.Done()
		done.Wait()

		if !adoptResp.Success {
			t.Fatalf("iteration %d: adopt failed: %s", i, adoptResp.Error)
		}
		if got := slotOf(t, deps.Store); got != "" {
			t.Fatalf("iteration %d: the slot holds a device master after the sign-out", i)
		}
		binding, _, err := keychain.GetAccountBinding(deps.Store)
		if err != nil || !binding.SignedOut {
			t.Fatalf("iteration %d: binding = %+v, err = %v", i, binding, err)
		}
	}
}

// An App login racing an adoption must leave the login's wrap in the slot.
func TestPersonalDEKAdopt_RacingLoginKeepsTheLoginWrap(t *testing.T) {
	for i := 0; i < 50; i++ {
		deps, _, deviceKey, stale := adoptFixture(t)
		login, err := aesGCMSeal(deviceKey, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		var (
			start sync.WaitGroup
			done  sync.WaitGroup
		)
		start.Add(1)
		done.Add(2)
		go func() {
			defer done.Done()
			start.Wait()
			adopt(deps, stale)
		}()
		go func() {
			defer done.Done()
			start.Wait()
			_ = keychain.SavePersonalDeviceWrappedDEK(deps.Store, login)
		}()
		start.Done()
		done.Wait()

		// Either the login wrote last, or the adoption saw the login's wrap
		// and left it. The stale copy can only remain if it went first and
		// the login then overwrote it, which also ends on the login's wrap.
		if got := slotOf(t, deps.Store); got != login {
			t.Fatalf("iteration %d: the slot does not hold the login's wrap", i)
		}
	}
}

// The old migration path: a supplied wrap still serves the call, but no
// longer reaches the slot, so it cannot undo a sign-out or replace a newer
// slot value.
func TestDEKUnwrapAndEncryptWithAAD_SuppliedWrapNeverReachesTheSlot(t *testing.T) {
	deps, _, deviceKey, wrapped := adoptFixture(t)
	seal := func() proto.BaseResponse {
		return HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{
			EncryptedDEKB64: wrapped,
			PlaintextB64:    base64.StdEncoding.EncodeToString([]byte("-")),
			AADB64:          base64.StdEncoding.EncodeToString([]byte("dragpass.extension.vault-move|1")),
		})
	}

	if resp := seal(); !resp.Success {
		t.Fatalf("seal with a supplied wrap: %s", resp.Error)
	}
	if got := slotOf(t, deps.Store); got != "" {
		t.Fatal("an empty slot was filled by a supplied wrap")
	}

	fresh, _ := aesGCMSeal(deviceKey, make([]byte, 32))
	if err := keychain.SavePersonalDeviceWrappedDEK(deps.Store, fresh); err != nil {
		t.Fatal(err)
	}
	if resp := seal(); !resp.Success {
		t.Fatalf("seal with a supplied wrap: %s", resp.Error)
	}
	if got := slotOf(t, deps.Store); got != fresh {
		t.Fatal("a supplied wrap replaced the slot value")
	}

	HandleDeviceSignout(deps, proto.DeviceSignoutRequest{})
	if resp := seal(); !resp.Success {
		t.Fatalf("seal with a supplied wrap: %s", resp.Error)
	}
	if got := slotOf(t, deps.Store); got != "" {
		t.Fatal("a supplied wrap undid the sign-out")
	}
}
