//go:build !keeper_e2e

package keystore

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	wrapOwnerID = "11111111-1111-4111-8111-111111111111"
	wrapPeerID  = "33333333-3333-4333-8333-333333333333"
)

// groupDEKWrapFrames builds a well-formed request for each Group DEK wrap
// action, so a refusal cannot be mistaken for a validation error. Each frame
// also claims to be the App every way a frame could.
func groupDEKWrapFrames(t *testing.T, app *App) map[string][]byte {
	t.Helper()
	ownPEM, _ := setupAppKeyPair(t, app)
	peer, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ownKey, err := keepercrypto.ParsePublicKey(ownPEM)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := keepercrypto.EncryptData(ownKey, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrappedB64 := base64.StdEncoding.EncodeToString(wrapped)
	payloads := map[string]any{
		proto.ActionGroupDEKGenerateAndOpen: map[string]any{"my_public_key": ownPEM},
		proto.ActionDEKRewrapForMember: map[string]any{
			"wrapped_for_me_b64": wrappedB64, "other_public_key": peer.PublicKey,
			"owner_account_id": wrapOwnerID, "other_account_id": wrapPeerID,
		},
		proto.ActionDEKUnwrapAndRewrapForMany: map[string]any{
			"wrapped_for_me_b64": wrappedB64, "owner_account_id": wrapOwnerID,
			"recipients": []map[string]any{{"account_id": wrapPeerID, "public_key": peer.PublicKey}},
		},
	}
	frames := make(map[string][]byte, len(payloads))
	for action, payload := range payloads {
		frame, err := json.Marshal(map[string]any{
			"action": action, "request_id": "x", "payload": payload,
			// Claims a frame can make; the caller comes from the transport.
			"caller": "app", "origin": "https://app.dragpass.io", "session": "session-a",
			"app_session": "session-a", "client": "app",
		})
		if err != nil {
			t.Fatal(err)
		}
		frames[action] = frame
	}
	return frames
}

// The Group DEK wrap actions run only for the paired App. A Native Messaging
// frame (the Extension, a proxying host, or any same-user process that starts
// Keeper on stdio) could otherwise name a key it holds and open bound tokens
// offline (protocol.md "Group DEK rewrap targets"). Whatever the frame claims,
// nothing runs: no keychain access (so no key read, no pin written), no Group
// DEK generated and no handle opened.
func TestHandleRequest_GroupDEKWrapActionsRefusedToNativeMessaging(t *testing.T) {
	app, _, store := newLeaseApp(t)
	frames := groupDEKWrapFrames(t, app)
	for action, frame := range frames {
		before := store.calls.Load()
		response := app.HandleRequest(frame)
		if response.Success || response.ErrorCode != ErrCodeChatAppCallerRequired ||
			response.RequestID != "x" || response.Data != nil {
			t.Fatalf("%s from Native Messaging: %+v", action, response)
		}
		if store.calls.Load() != before {
			t.Fatalf("%s touched the keychain although it was refused", action)
		}
	}
	if opened := app.GroupSessions.CloseAll(); opened != 0 {
		t.Fatalf("a refused frame opened %d Group DEK handles", opened)
	}
}

// The same requests run from the App's authenticated entry, so the refusal
// above is the caller gate and not a malformed request.
func TestHandleAppRequest_GroupDEKWrapActionsRunForTheApp(t *testing.T) {
	app, _, _ := newLeaseApp(t)
	for action, frame := range groupDEKWrapFrames(t, app) {
		response := app.HandleAppRequest(sessionA, "", frame)
		if !response.Success {
			t.Fatalf("%s from the App: %+v", action, response)
		}
	}
}
