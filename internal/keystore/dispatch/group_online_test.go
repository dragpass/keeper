package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestDirectGroupClipboardRequestRequiresOnlineProof(t *testing.T) {
	response := HandleRequestGated(testdouble.NewMemoryLogger(), handlers.Deps{},
		[]byte(`{"action":"group_decrypt_to_clipboard","request_id":"online-test","payload":{}}`), nil)
	if response.Success || response.ErrorCode != "online_revocation_check_required" {
		t.Fatal("direct group clipboard action bypassed online proof")
	}
}
