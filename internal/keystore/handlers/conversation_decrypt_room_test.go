// conversation_decrypt_room_test.go — the room-name branch of the chat reveal
// (0.0.34, payload_kind).
//
// The room vector shares the key, IV, org, conversation, and dek_version of
// conversation_decrypt_test.go's chat vector and differs only in the AAD
// domain. That is deliberate: in a real room the name and the messages are
// sealed under one DEK at one epoch, so the domain string is the *only* thing
// standing between them. Sharing everything else here means these tests fail
// the moment that one thing stops doing its job.
//
// The harness (chatFixture, msgTestVerifier, msgTestClock, msgTestServerKey) is
// the one conversation_decrypt_test.go and message_display_test.go already use.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	// Sealed with chatKeyHex + chatIV1B64 under
	// dragpass.room|1|<chatOrgID>|<chatConvID>|5. Non-ASCII on purpose: a room
	// name is user text and the UTF-8 check on the way out has to pass it.
	roomNameCtB64  = "GCA8wBpUmJ+cEnlvBhU3RGcFmwFKfsh0on91G4rta+v0GnqAyZxcCQ=="
	roomNameB64    = "RHJhZ1Bhc3Mg67CpIGZpeHR1cmUgb25l"
	roomNamePlain  = "DragPass 방 fixture one"
	unknownKind    = "room"
	messageKindLit = "message"
)

// signRoom signs a permit over the room-name canonical instead of the message
// one. Everything else about the permit is identical, which is the point.
func (f *chatFixture) signRoom(t *testing.T, p proto.ConversationReadPermit) proto.ConversationReadPermit {
	t.Helper()
	sig, err := crypto.SignData(f.key, proto.RoomNameReadPermitCanonical(p))
	if err != nil {
		t.Fatalf("sign room permit: %v", err)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}

// roomRequest returns the one-entry room-name batch, minus the permit.
func (f *chatFixture) roomRequest() proto.ConversationDecryptBatchForAppDisplayRequest {
	r := f.request()
	r.PayloadKind = proto.ConversationPayloadKindRoomName
	r.Messages = []proto.ConversationDecryptMessage{
		{IVB64: chatIV1B64, CiphertextB64: roomNameCtB64},
	}
	return r
}

// roomAuthorized is the flow that is known to work, so the tests that break one
// thing start from it.
func (f *chatFixture) roomAuthorized(t *testing.T) proto.ConversationDecryptBatchForAppDisplayRequest {
	t.Helper()
	r := f.roomRequest()
	r.Permit = f.signRoom(t, f.unsignedPermit(r))
	return r
}

// ────────────────────────────────────────────────────────────────────────
// Happy path
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_RoomName_HappyPath(t *testing.T) {
	f := newChatFixture(t)
	resp := f.display(t, f.roomAuthorized(t))
	assertChatPlaintexts(t, resp, roomNameB64)
}

func TestConversationDecrypt_RoomName_PlaintextNeverLogged(t *testing.T) {
	f := newChatFixture(t)
	assertChatPlaintexts(t, f.display(t, f.roomAuthorized(t)), roomNameB64)
	if f.log.Contains(roomNamePlain) || f.log.Contains(roomNameB64) {
		t.Fatal("room name leaked into the log buffer")
	}
}

// An omitted payload_kind is the 0.0.33 wire, and it has to keep meaning
// "message" — both on the way in (the strict decoder must not demand the key)
// and on the way out (a message request must not start emitting one).
func TestConversationDecrypt_OmittedPayloadKind_IsMessage(t *testing.T) {
	f := newChatFixture(t)

	req := f.authorized(t)
	payload := chatMarshal(t, req)
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, present := object["payload_kind"]; present {
		t.Fatal("a message request must not serialize payload_kind — 0.0.33 Keepers reject unknown keys")
	}
	assertChatPlaintexts(t, f.displayRaw(payload), chatPt1B64, chatPt2B64)
}

func TestConversationDecrypt_ExplicitMessageKind_IsMessage(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	req.PayloadKind = messageKindLit
	req.Permit = f.signedPermit(t, req)
	assertChatPlaintexts(t, f.display(t, req), chatPt1B64, chatPt2B64)
}

// ────────────────────────────────────────────────────────────────────────
// Domain separation: the permit half
//
// Neither permit carries a domain field, so the only thing telling the two
// apart is which canonical the Keeper rebuilds. Choosing the canonical is the
// binding check — these two cases are what fixes that.
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_MessagePermitInRoomRequest_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.roomRequest()
	req.Permit = f.signedPermit(t, req) // signed over dragpass.chat.read
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

func TestConversationDecrypt_RoomPermitInMessageRequest_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	req.Permit = f.signRoom(t, f.unsignedPermit(req)) // signed over dragpass.room.read
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

// ────────────────────────────────────────────────────────────────────────
// Domain separation: the AAD half
//
// Same key, same IV, same conversation, same epoch, correctly signed permit for
// the mode being asked for — and the ciphertext still does not open, because it
// was sealed under the other domain.
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_ChatCiphertextInRoomMode_DecryptFailed(t *testing.T) {
	f := newChatFixture(t)
	req := f.roomRequest()
	req.Messages = []proto.ConversationDecryptMessage{
		{IVB64: chatIV1B64, CiphertextB64: chatCt1B64}, // sealed under dragpass.chat
	}
	req.Permit = f.signRoom(t, f.unsignedPermit(req))
	resp := f.display(t, req)
	assertChatFailure(t, resp, proto.ChatErrorCodeDecryptFailed)
	if f.log.Contains(chatPt1Plain) || f.log.Contains(chatPt1B64) {
		t.Fatal("plaintext leaked into the log buffer")
	}
}

func TestConversationDecrypt_RoomCiphertextInMessageMode_DecryptFailed(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	req.Messages = []proto.ConversationDecryptMessage{
		{IVB64: chatIV1B64, CiphertextB64: roomNameCtB64}, // sealed under dragpass.room
	}
	req.Permit = f.signedPermit(t, req)
	resp := f.display(t, req)
	assertChatFailure(t, resp, proto.ChatErrorCodeDecryptFailed)
	if f.log.Contains(roomNamePlain) || f.log.Contains(roomNameB64) {
		t.Fatal("room name leaked into the log buffer")
	}
}

// A ciphertext from outside the chat action entirely — a drag token (no AAD)
// and a Secure Message — must fail in the room branch too. The room branch is
// not a looser door into the same key.
func TestConversationDecrypt_RoomName_ForeignCiphertext_DecryptFailed(t *testing.T) {
	cases := []struct {
		name    string
		foreign string
	}{
		{"non-aad", chatForeignNonAADB64},
		{"secure-message aad", chatForeignMsgAADB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatFixture(t)
			req := f.roomRequest()
			req.Messages = []proto.ConversationDecryptMessage{
				{IVB64: chatIV1B64, CiphertextB64: tc.foreign},
			}
			req.Permit = f.signRoom(t, f.unsignedPermit(req))
			assertChatFailure(t, f.display(t, req), proto.ChatErrorCodeDecryptFailed)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// The room_name single-entry constraint
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_RoomName_BatchMustBeExactlyOne(t *testing.T) {
	cases := []struct {
		name     string
		messages []proto.ConversationDecryptMessage
	}{
		{"empty", nil},
		{"two", []proto.ConversationDecryptMessage{
			{IVB64: chatIV1B64, CiphertextB64: roomNameCtB64},
			{IVB64: chatIV1B64, CiphertextB64: roomNameCtB64},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatFixture(t)
			req := f.roomRequest()
			req.Messages = tc.messages
			req.Permit = f.signRoom(t, f.unsignedPermit(req))
			assertChatFailure(t, f.display(t, req), proto.ChatErrorCodeInvalidInput)
		})
	}
}

func TestConversationDecrypt_UnknownPayloadKind_InvalidInput(t *testing.T) {
	f := newChatFixture(t)
	req := f.roomRequest()
	req.PayloadKind = unknownKind
	req.Permit = f.signRoom(t, f.unsignedPermit(req))
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodeInvalidInput)
}

// An empty string on the wire is not the same thing as an absent key, and it
// must not become a third spelling of "message": the enum has two values.
func TestConversationDecrypt_EmptyPayloadKindOnWire_IsMessage(t *testing.T) {
	f := newChatFixture(t)
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(chatMarshal(t, f.authorized(t)), &object); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	object["payload_kind"] = json.RawMessage(`""`)
	assertChatPlaintexts(t, f.displayRaw(chatMarshal(t, object)), chatPt1B64, chatPt2B64)
}

// ────────────────────────────────────────────────────────────────────────
// Everything the message branch already enforces still holds in room mode
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_RoomName_WindowAndBinding(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomAuthorized(t)
		f.clock.advance(proto.ChatReadPermitTTLSeconds + 1)
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
	t.Run("issued_at too far in the future", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomRequest()
		permit := f.unsignedPermit(req)
		permit.IssuedAt = chatNowUnix + 10 // skew allows only +5
		permit.ExpiresAt = permit.IssuedAt + proto.ChatReadPermitTTLSeconds
		req.Permit = f.signRoom(t, permit)
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
	t.Run("window not exactly 300", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomRequest()
		permit := f.unsignedPermit(req)
		permit.ExpiresAt = permit.IssuedAt + 600
		req.Permit = f.signRoom(t, permit)
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
	t.Run("unknown server key version", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomRequest()
		permit := f.unsignedPermit(req)
		permit.ServerKeyVersion = msgServerKeyVersion + 1
		req.Permit = f.signRoom(t, permit)
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
	t.Run("conversation_id disagrees with the permit", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomAuthorized(t)
		req.ConversationID = chatOtherUUID
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
	t.Run("closed handle", func(t *testing.T) {
		f := newChatFixture(t)
		req := f.roomAuthorized(t)
		f.deps.GroupSessions.Close(f.handle)
		assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
	})
}
