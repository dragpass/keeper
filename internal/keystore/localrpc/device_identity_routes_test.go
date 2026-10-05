package localrpc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const routeCandidate = "33333333-3333-4333-8333-333333333333"

// The App's whole device identity flow through its routes: adopt its old id,
// write the binding, read the status, sign the device out. No answer carries
// the account private key, the device key or the device master.
func TestDeviceIdentityRoutes(t *testing.T) {
	server := newTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	account := routeKeypair(t)
	if err := keychain.SavePrivateKey(store, account.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, account.PublicKey); err != nil {
		t.Fatal(err)
	}
	const deviceKey = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo="
	if err := keychain.SaveDeviceKey(store, deviceKey); err != nil {
		t.Fatal(err)
	}
	const wrapped = "WRAPPED_DEVICE_MASTER_SENTINEL"
	if err := keychain.SavePersonalDeviceWrappedDEK(store, wrapped); err != nil {
		t.Fatal(err)
	}
	session, csrf := openTestSession(t, server)
	var bodies []string
	call := func(path string, body any, into any) {
		t.Helper()
		code, result, raw := callRoute(t, server, session, csrf, path, body)
		if code != http.StatusOK || !result.Success {
			t.Fatalf("%s: %d %s", path, code, raw)
		}
		bodies = append(bodies, string(result.Data))
		if err := json.Unmarshal(result.Data, into); err != nil {
			t.Fatal(err)
		}
	}

	var id proto.DeviceIDEnsureResponseData
	call("/v1/device/id", map[string]string{"candidate_device_id": routeCandidate}, &id)
	if id.DeviceID != routeCandidate || id.Source != "candidate" {
		t.Fatalf("device id = %+v", id)
	}
	var again proto.DeviceIDEnsureResponseData
	call("/v1/device/id", map[string]string{}, &again)
	if again.DeviceID != routeCandidate || again.Source != "stored" {
		t.Fatalf("second device id = %+v", again)
	}

	var bound proto.AccountBindingSetResponseData
	call("/v1/account/binding", map[string]string{"account_id": routeOwner, "alias": "alice"}, &bound)
	if !bound.Changed || bound.Generation != 1 {
		t.Fatalf("binding = %+v", bound)
	}

	var status proto.DeviceAccountStatusResponseData
	call("/v1/device/status", map[string]string{}, &status)
	if status.DeviceID != routeCandidate || status.AccountID != routeOwner || status.Alias != "alice" ||
		!status.DeviceMasterPresent || status.SignedOut || status.AccountKeyFingerprint == "" {
		t.Fatalf("status = %+v", status)
	}

	if _, _, err := server.app.GroupSessions.Open(bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	var signedOut proto.DeviceSignoutResponseData
	call("/v1/device/signout", map[string]string{}, &signedOut)
	if !signedOut.DeviceMasterRemoved || signedOut.ClosedGroupSessions != 1 {
		t.Fatalf("signout = %+v", signedOut)
	}
	call("/v1/device/status", map[string]string{}, &status)
	if !status.SignedOut || status.DeviceMasterPresent {
		t.Fatalf("status after signout = %+v", status)
	}
	if got, _ := keychain.GetPrivateKey(store); got != account.PrivateKey {
		t.Fatal("the sign-out removed the account key")
	}

	for _, body := range bodies {
		for _, secret := range []string{account.PrivateKey, account.PublicKey, deviceKey, wrapped} {
			if strings.Contains(body, secret) {
				t.Fatalf("a device identity route answered key material: %s", body)
			}
		}
	}
}

// Each route takes only its own fields, and the action's validation still
// runs behind the route.
func TestDeviceIdentityRoutesRefuseOtherShapes(t *testing.T) {
	server := newTestServer(t)
	session, csrf := openTestSession(t, server)
	for path, body := range map[string]any{
		"/v1/device/id":       map[string]string{"device_id": routeCandidate},
		"/v1/account/binding": map[string]string{"account_id": routeOwner, "alias": "alice", "generation": "9"},
		"/v1/device/status":   map[string]bool{"include_keys": true},
		"/v1/device/signout":  map[string]bool{"wipe_account_key": true},
	} {
		if code, _, raw := callRoute(t, server, session, csrf, path, body); code != http.StatusBadRequest {
			t.Errorf("%s with a foreign field: %d %s", path, code, raw)
		}
	}
	code, result, _ := callRoute(t, server, session, csrf, "/v1/device/id", map[string]string{"candidate_device_id": "NOT-A-UUID"})
	if code != http.StatusOK || result.Success || result.ErrorCode != "validation_error" {
		t.Fatalf("a bad candidate: %d %+v", code, result)
	}
	code, result, _ = callRoute(t, server, session, csrf, "/v1/account/binding", map[string]string{"account_id": routeOwner, "alias": "alice"})
	if code != http.StatusOK || result.Success || result.ErrorCode != "not_found" {
		t.Fatalf("a binding without an account key: %d %+v", code, result)
	}
}

func TestDeviceIdentityRoutesNeedASession(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/v1/device/id", "/v1/account/binding", "/v1/device/status", "/v1/device/signout"} {
		if response := localRequest(server, http.MethodPost, path, `{}`, "", ""); response.Code == http.StatusOK {
			t.Fatalf("%s answered without a session", path)
		}
	}
}
