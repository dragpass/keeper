package localrpc

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// The App route derives the seed of the golden vector, answers nothing but
// the seed, and leaves the keyring as it was. A field the action does not
// know (a caller-chosen salt or info) is refused by the strict decode.
func TestAppOrgEmergencySeedRouteDerivesWithoutWriting(t *testing.T) {
	server := newTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)
	before := store.Snapshot()

	const orgID, code = "5b0e8b8e-3f4a-4c55-9d2e-0a1b2c3d4e5f", "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	status, result, body := callRoute(t, server, session, csrf, "/v1/auth/org-emergency/seed",
		map[string]string{"org_id": orgID, "code": code})
	if status != http.StatusOK || !result.Success || strings.Contains(body, code) {
		t.Fatalf("seed: %d %s", status, body)
	}
	var data proto.OrgEmergencySeedDeriveResponseData
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Seed != "Kvx796nq9FhlCYegD0zlpjhBp/ec4tZmQDOiwooGAag=" {
		t.Fatalf("seed = %s", data.Seed)
	}
	var fields map[string]any
	_ = json.Unmarshal(result.Data, &fields)
	if len(fields) != 1 {
		t.Fatalf("the answer carries more than the seed: %v", fields)
	}

	status, _, _ = callRoute(t, server, session, csrf, "/v1/auth/org-emergency/seed",
		map[string]string{"org_id": orgID, "code": code, "info": "dragpass-recovery-auth-v1"})
	if status != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted: %d", status)
	}
	status, result, _ = callRoute(t, server, session, csrf, "/v1/auth/org-emergency/seed",
		map[string]string{"org_id": strings.ToUpper(orgID), "code": code})
	if status == http.StatusOK && result.Success {
		t.Fatal("an uppercase org id derived a seed")
	}

	if !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatal("the seed route wrote to the keyring")
	}
}
