package localrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// interleaveAfter sends a Native Messaging frame right after a composed
// route's first step, the moment another caller could otherwise slip in
// between its steps, and records whether that frame finished before the
// route did. It returns a wait for the frame's answer.
func interleaveAfter(t *testing.T, server *Server, first, frame string) func() proto.BaseResponse {
	t.Helper()
	answered := make(chan proto.BaseResponse, 1)
	var once sync.Once
	server.onAction = func(action string, _ []byte, _ proto.BaseResponse) {
		if action != first {
			return
		}
		once.Do(func() {
			go func() { answered <- server.app.HandleRequest([]byte(frame)) }()
			select {
			case response := <-answered:
				answered <- response
				t.Errorf("%s ran between the steps of a composed route", frame)
			case <-time.After(150 * time.Millisecond):
			}
		})
	}
	return func() proto.BaseResponse {
		select {
		case response := <-answered:
			return response
		case <-time.After(5 * time.Second):
			t.Fatalf("%s never ran", frame)
			return proto.BaseResponse{}
		}
	}
}

func TestAppPasswordRewrapRunsAsOneUnit(t *testing.T) {
	server := newTestServer(t)
	if err := keychain.SaveDeviceKey(server.app.Store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))); err != nil {
		t.Fatal(err)
	}
	current := passwordWrap(t, "current-password", bytes.Repeat([]byte{0x22}, 32))
	session, csrf := openTestSession(t, server)
	wait := interleaveAfter(t, server, proto.ActionDEKRotateToDeviceKey, `{"action":"`+proto.ActionDeleteDeviceKey+`"}`)

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/password/rewrap", map[string]string{
		"password": "current-password", "encrypted_dek_b64": current, "new_password": "new-password",
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rewrap: %d %s", code, body)
	}
	if response := wait(); !response.Success {
		t.Fatalf("the device key delete after the rewrap: %+v", response)
	}
}

func TestAppDeviceForgetRunsAsOneUnit(t *testing.T) {
	server, store, _, session, csrf := newKeyedRouteServer(t)
	_ = keychain.SaveDeviceKey(store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	wait := interleaveAfter(t, server, proto.ActionDeviceKeyStatus, `{"action":"`+proto.ActionDeleteDeviceKey+`"}`)

	code, result, body := callRoute(t, server, session, csrf, "/v1/device/forget", map[string]any{})
	if code != http.StatusOK || !result.Success || string(result.Data) != `{"forgotten":true}` {
		t.Fatalf("forget: %d %s", code, body)
	}
	// The concurrent delete lands after the forget and finds nothing.
	if response := wait(); response.Success || response.ErrorCode == "unsupported" {
		t.Fatalf("the concurrent delete still found a device key: %+v", response)
	}
}

func TestRoomRowNameSealRunsAsOneUnit(t *testing.T) {
	server, _ := newChatTestServer(t)
	own := routeKeypair(t)
	_ = keychain.SavePrivateKey(server.app.Store, own.PrivateKey)
	_ = keychain.SavePublicKey(server.app.Store, own.PublicKey)
	session, csrf := openTestSession(t, server)
	// A device sign-out closes every group handle, the throwaway one too.
	wait := interleaveAfter(t, server, proto.ActionGroupDEKGenerateAndOpen, `{"action":"device_signout"}`)

	code, result, body := callRoute(t, server, session, csrf, "/v1/chat/room_row_name_seal", map[string]string{
		"org_id":          "66666666-6666-4666-8666-666666666666",
		"conversation_id": "77777777-7777-4777-8777-777777777777",
		"plaintext_b64":   base64.StdEncoding.EncodeToString([]byte("room")),
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("seal: %d %s", code, body)
	}
	if response := wait(); !response.Success {
		t.Fatalf("the sign-out after the seal: %+v", response)
	}
}

// The golden vector dragpass packages/crypto/lib/chat-aad.test.ts pins for
// canonicalRoomNameAad. Keeper builds the room name AAD itself, so the two
// builders must agree byte for byte.
func TestRoomNameAADMatchesTheDragpassGoldenVector(t *testing.T) {
	const want = "64726167706173732e726f6f6d7c317c36363636363636362d363636362d343636362d383636362d3636363636363636363636367c37373737373737372d373737372d343737372d383737372d3737373737373737373737377c33"
	got := hex.EncodeToString([]byte(roomNameAAD("66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777", "3")))
	if got != want {
		t.Fatalf("room name AAD = %s", got)
	}
}
