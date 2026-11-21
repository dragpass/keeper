package localrpc

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestReconfigurationStageUsesInitiatingAppLogin(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)
	login := func(account string) proto.ArchiveLoginIdentity {
		b, _, err := keychain.SetAccountBinding(store, account, "stage", true)
		if err != nil {
			t.Fatal(err)
		}
		return proto.ArchiveLoginIdentity{AccountID: b.AccountID, Generation: b.ChatStateGeneration}
	}
	if err := store.Set(config.Service, config.DeviceID, routeOwner); err != nil {
		t.Fatal(err)
	}
	old := login(routeOwner)
	body := map[string]any{"org_id": routeOnlyOrg, "operation_id": routePeer}
	request := func(t *testing.T, expectCode string) {
		t.Helper()
		before := store.Snapshot()
		status, result, _ := callRoute(t, server, session, csrf, "/v1/archive/archive_reconfigure_stage", body)
		if status != http.StatusOK || result.ErrorCode != expectCode || result.Success != (expectCode == "") {
			t.Fatalf("stage HTTP %d success %v code %q, want %q", status, result.Success, result.ErrorCode, expectCode)
		}
		if expectCode != "" && (len(result.Data) != 0 || !reflect.DeepEqual(before, store.Snapshot())) {
			t.Fatal("refused stage disclosed data or modified the store")
		}
	}
	t.Run("missing initiating login", func(t *testing.T) { request(t, "validation_error") })
	body["app_login"] = old
	login(routePeer)
	t.Run("delivery after account switch", func(t *testing.T) { request(t, "archive_session_login_unavailable") })
	current := login(routeOwner)
	t.Run("delivery after same account signs back in", func(t *testing.T) { request(t, "archive_session_login_unavailable") })
	body["app_login"] = current
	request(t, "")
	body["app_login"] = old
	request(t, "archive_session_login_unavailable")
}
