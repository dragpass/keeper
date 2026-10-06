package dispatch

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// A request payload carries passwords, recovery keys and plaintext. Once its
// handler has returned, the dispatcher's copy of it is wiped.
func TestHandleRequestGatedWipesThePayloadAfterTheHandler(t *testing.T) {
	const action = "test_capture_payload"
	var captured json.RawMessage
	actionRegistry[action] = func(_ handlers.Deps, payload json.RawMessage) proto.BaseResponse {
		captured = payload
		return proto.BaseResponse{Success: true}
	}
	defer delete(actionRegistry, action)

	log := testdouble.NewMemoryLogger()
	response := HandleRequestGated(log, handlers.Deps{Logger: log}, []byte(`{"action":"`+action+`","payload":{"password":"correct horse"}}`), nil)
	if !response.Success || len(captured) == 0 {
		t.Fatalf("the handler did not run: %+v", response)
	}
	if !bytes.Equal(captured, make([]byte, len(captured))) {
		t.Fatalf("the payload outlived its handler: %q", captured)
	}
}
