// device_key_status_ensure_test.go — device_key_status / device_key_ensure.
//
// Defects these tests catch:
//   - a response, error or log line carrying the stored device key
//   - ensure overwriting an existing or malformed key (orphaning the
//     device-wrapped DEK it sealed)
//   - two concurrent ensures each minting and storing a key
package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

type failingSetStore struct {
	*testdouble.MemorySecretStore
}

func (failingSetStore) Set(string, string, string) error {
	return errors.New("backend refused value " + deviceKeySentinelB64)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// 32 bytes of 0x5A; a recognisable value to look for in output.
var deviceKeySentinelB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 32))

func assertNoDeviceKeyLeak(t *testing.T, log *testdouble.MemoryLogger, resp proto.BaseResponse, key string) {
	t.Helper()
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), key) {
		t.Fatalf("response carries the device key: %s", encoded)
	}
	if log.Contains(key) {
		t.Fatalf("logger leaked the device key: %v", log.Messages())
	}
}

func storedDeviceKey(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	key, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey: %v", err)
	}
	return key
}

func TestHandleDeviceKeyStatus_Absent(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleDeviceKeyStatus(deps, proto.DeviceKeyStatusRequest{})
	if !resp.Success {
		t.Fatalf("status: %s", resp.Error)
	}
	if resp.Data.(proto.DeviceKeyStatusResponseData).Present {
		t.Fatal("present = true on an empty keychain")
	}
}

func TestHandleDeviceKeyStatus_PresentWithoutKeyBytes(t *testing.T) {
	deps, log, store := newTestDeps(t)
	if err := keychain.SaveDeviceKey(store, deviceKeySentinelB64); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceKeyStatus(deps, proto.DeviceKeyStatusRequest{})
	if !resp.Success || !resp.Data.(proto.DeviceKeyStatusResponseData).Present {
		t.Fatalf("status = %+v, want present", resp)
	}
	assertNoDeviceKeyLeak(t, log, resp, deviceKeySentinelB64)
}

func TestHandleDeviceKeyStatus_InvalidStoredKeyIsNotEchoed(t *testing.T) {
	deps, log, store := newTestDeps(t)
	const malformed = "NOT_A_32_BYTE_KEY_DO_NOT_LEAK"
	if err := keychain.SaveDeviceKey(store, malformed); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceKeyStatus(deps, proto.DeviceKeyStatusRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("status = %+v, want storage_failure", resp)
	}
	assertNoDeviceKeyLeak(t, log, resp, malformed)
}

func TestHandleDeviceKeyEnsure_CreatesOnceInsideKeeper(t *testing.T) {
	deps, log, store := newTestDeps(t)
	resp := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if !resp.Success || !resp.Data.(proto.DeviceKeyEnsureResponseData).Created {
		t.Fatalf("first ensure = %+v, want created", resp)
	}
	key := storedDeviceKey(t, store)
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		t.Fatal("ensure stored something other than Base64 of 32 bytes")
	}
	assertNoDeviceKeyLeak(t, log, resp, key)

	again := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if !again.Success || again.Data.(proto.DeviceKeyEnsureResponseData).Created {
		t.Fatalf("second ensure = %+v, want created=false", again)
	}
	if storedDeviceKey(t, store) != key {
		t.Fatal("a repeated ensure replaced the device key")
	}
	assertNoDeviceKeyLeak(t, log, again, key)
}

func TestHandleDeviceKeyEnsure_KeepsExistingKey(t *testing.T) {
	deps, log, store := newTestDeps(t)
	if err := keychain.SaveDeviceKey(store, deviceKeySentinelB64); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if !resp.Success || resp.Data.(proto.DeviceKeyEnsureResponseData).Created {
		t.Fatalf("ensure = %+v, want created=false", resp)
	}
	if storedDeviceKey(t, store) != deviceKeySentinelB64 {
		t.Fatal("ensure replaced an existing device key")
	}
	assertNoDeviceKeyLeak(t, log, resp, deviceKeySentinelB64)
}

func TestHandleDeviceKeyEnsure_RefusesToReplaceMalformedKey(t *testing.T) {
	deps, log, store := newTestDeps(t)
	const malformed = "NOT_A_32_BYTE_KEY_DO_NOT_LEAK"
	if err := keychain.SaveDeviceKey(store, malformed); err != nil {
		t.Fatal(err)
	}
	resp := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("ensure = %+v, want storage_failure", resp)
	}
	if storedDeviceKey(t, store) != malformed {
		t.Fatal("ensure overwrote a malformed device key")
	}
	assertNoDeviceKeyLeak(t, log, resp, malformed)
}

func TestHandleDeviceKeyEnsure_RandomFailureStoresNothing(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deps.Rand = failingReader{}
	resp := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeInternal) {
		t.Fatalf("ensure = %+v, want internal_error", resp)
	}
	if _, err := keychain.GetDeviceKey(store); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatalf("a failed generation stored a key (err=%v)", err)
	}
}

func TestHandleDeviceKeyEnsure_StoreErrorTextIsNotEchoed(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	deps.Store = failingSetStore{testdouble.NewMemorySecretStore()}
	resp := HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("ensure = %+v, want storage_failure", resp)
	}
	assertNoDeviceKeyLeak(t, log, resp, deviceKeySentinelB64)
}

func TestHandleDeviceKeyEnsure_ConcurrentCallsStoreOneKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	const callers = 16
	var wg sync.WaitGroup
	results := make(chan proto.BaseResponse, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- HandleDeviceKeyEnsure(deps, proto.DeviceKeyEnsureRequest{})
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for resp := range results {
		if !resp.Success {
			t.Fatalf("ensure: %s", resp.Error)
		}
		if resp.Data.(proto.DeviceKeyEnsureResponseData).Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created = %d across %d concurrent ensures, want 1", created, callers)
	}
	if storedDeviceKey(t, store) == "" {
		t.Fatal("no device key stored")
	}
}
