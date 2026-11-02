//go:build !keeper_e2e

package keystore

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The Group DEK wrap actions run only for the paired App. A Native Messaging
// frame (the Extension, a proxying host, or any same-user process that starts
// Keeper on stdio) could otherwise name a key it holds and open bound tokens
// offline (protocol.md "Group DEK rewrap targets").
func TestHandleRequest_GroupDEKWrapActionsRefusedToNativeMessaging(t *testing.T) {
	app, _, store := newLeaseApp(t)
	for _, action := range []string{
		proto.ActionGroupDEKGenerateAndOpen,
		proto.ActionDEKRewrapForMember,
		proto.ActionDEKUnwrapAndRewrapForMany,
	} {
		before := store.calls.Load()
		frame, _ := json.Marshal(map[string]any{"action": action, "request_id": "x", "payload": map[string]any{}})
		response := app.HandleRequest(frame)
		if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired || response.RequestID != "x" {
			t.Fatalf("%s from Native Messaging: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s ran although it was refused", action)
		}
	}
}
