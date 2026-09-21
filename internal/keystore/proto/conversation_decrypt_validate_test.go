// conversation_decrypt_validate_test.go — structural validation of the chat
// batch-decrypt request and the two chat canonical builders.
//
// The canonical tests carry literal expected strings on purpose. CC1
// (packages/crypto) builds the same chat AAD bytes on the encrypt side, and
// CC2 (ariadne) builds the same conversation-read-permit canonical on the
// signing side; if any of them drifts by one character, every message either
// fails to open or fails signature verification. A literal is the only
// assertion that catches that, and the tests print the literals so the CC2
// agent can match identical bytes.
//
// VALID_HANDLE is declared in aes_actions_validate_test.go (same package).

package proto

import (
	"strings"
	"testing"
)

const (
	chatFixtureOrgID      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	chatFixtureConvID     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	chatFixtureAccountID  = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	chatFixtureDekVersion = 5
	chatFixtureIssuedAt   = 1700000000
	chatFixtureExpiresAt  = 1700000300 // issued_at + 300
	// chatFixtureIVB64 / chatFixtureCt1B64 come from the CC0 AES-256-GCM vector
	// (key 0x20..0x3f, chat AAD dragpass.chat|1|<org>|<conv>|5), test-only.
	chatFixtureIVB64  = "AAECAwQFBgcICQoL"
	chatFixtureCt1B64 = "GCA8wBpUmJ+cmqGnUlMzWWADiAMPMcl/QQeov7RajOdKoFQy06tZ+Ufw"

	// chatAADGolden / chatPermitCanonicalGolden — the exact bytes CC1 and CC2
	// must reproduce. Kept as literals here and asserted below.
	chatAADGolden = "dragpass.chat|1|" +
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa|" +
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb|5"
	chatPermitCanonicalGolden = "dragpass.chat.read|1|" +
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc|" +
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa|" +
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb|5|" +
		"1700000000|1700000300|1"
)

func chatValidPermit() ConversationReadPermit {
	return ConversationReadPermit{
		AccountID:        chatFixtureAccountID,
		OrgID:            chatFixtureOrgID,
		ConversationID:   chatFixtureConvID,
		DekVersion:       chatFixtureDekVersion,
		IssuedAt:         chatFixtureIssuedAt,
		ExpiresAt:        chatFixtureExpiresAt,
		ServerKeyVersion: 1,
		Signature:        "aGVsbG8=",
	}
}

func chatValidRequest() ConversationDecryptBatchForAppDisplayRequest {
	return ConversationDecryptBatchForAppDisplayRequest{
		GroupHandle:    VALID_HANDLE,
		Permit:         chatValidPermit(),
		OrgID:          chatFixtureOrgID,
		ConversationID: chatFixtureConvID,
		DekVersion:     chatFixtureDekVersion,
		Messages: []ConversationDecryptMessage{
			{IVB64: chatFixtureIVB64, CiphertextB64: chatFixtureCt1B64},
		},
	}
}

// ────────────────────────────────────────────────────────────────────────
// Canonicals (golden literals; printed for the CC2 agent)
// ────────────────────────────────────────────────────────────────────────

// TestChatAADCanonical_GoldenVector — the chat AAD literal. The Keeper builds
// this itself; a caller cannot supply it, which is what keeps a drag token, a
// Secure Message, and a credential payload from opening through the chat action.
func TestChatAADCanonical_GoldenVector(t *testing.T) {
	got := ChatAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion)
	t.Logf("CHAT AAD canonical (golden): %s", got)
	if got != chatAADGolden {
		t.Fatalf("chat AAD = %q, want %q", got, chatAADGolden)
	}
	if strings.Count(got, "|") != 4 {
		t.Fatalf("chat AAD must have 5 items separated by 4 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("chat AAD must not end with a newline")
	}
}

// TestConversationReadPermitCanonical_GoldenVector — the 9-item signing string
// on fixed inputs. ariadne's signer (CC2) asserts the same literal.
func TestConversationReadPermitCanonical_GoldenVector(t *testing.T) {
	got := ConversationReadPermitCanonical(chatValidPermit())
	t.Logf("conversation-read-permit canonical (golden): %s", got)
	if got != chatPermitCanonicalGolden {
		t.Fatalf("permit canonical = %q, want %q", got, chatPermitCanonicalGolden)
	}
	if strings.Count(got, "|") != 8 {
		t.Fatalf("canonical must have 9 items separated by 8 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("canonical must not end with a newline")
	}
}

// TestChatAADCanonical_DomainSeparation — the chat AAD differs from the Secure
// Message AAD and the credential canonical, so a ciphertext sealed under one
// cannot open under another.
func TestChatAADCanonical_DomainSeparation(t *testing.T) {
	chat := ChatAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion)
	message := MessageAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion, MessageSchemaVersion, 2000000000)
	if chat == message {
		t.Fatal("chat AAD and message AAD must not be byte-identical")
	}
	if !strings.HasPrefix(chat, "dragpass.chat|") {
		t.Fatalf("chat AAD must start with the chat domain, got %q", chat)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Validate
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_Validate_AcceptsFixture(t *testing.T) {
	if err := chatValidRequest().Validate(); err != nil {
		t.Fatalf("fixture request rejected: %v", err)
	}
	// An empty batch is a valid no-op (empty in → empty out).
	empty := chatValidRequest()
	empty.Messages = nil
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty-batch request rejected: %v", err)
	}
	// The maximum batch is accepted.
	full := chatValidRequest()
	full.Messages = make([]ConversationDecryptMessage, ConversationDecryptMaxMessages)
	for i := range full.Messages {
		full.Messages[i] = ConversationDecryptMessage{IVB64: chatFixtureIVB64, CiphertextB64: chatFixtureCt1B64}
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("max-batch request rejected: %v", err)
	}
}

func TestConversationDecrypt_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*ConversationDecryptBatchForAppDisplayRequest)
		field string
	}{
		{"empty handle", func(r *ConversationDecryptBatchForAppDisplayRequest) { r.GroupHandle = "" }, "group_handle"},
		{"uppercase org uuid", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.OrgID = "AABBCCDD-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}, "org_id"},
		{"nil conversation uuid", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.ConversationID = "00000000-0000-0000-0000-000000000000"
		}, "conversation_id"},
		{"unhyphenated conversation uuid", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.ConversationID = strings.ReplaceAll(chatFixtureConvID, "-", "")
		}, "conversation_id"},
		{"zero dek version", func(r *ConversationDecryptBatchForAppDisplayRequest) { r.DekVersion = 0 }, "dek_version"},
		{"dek version over int32", func(r *ConversationDecryptBatchForAppDisplayRequest) { r.DekVersion = 2147483648 }, "dek_version"},
		{"batch over cap", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages = make([]ConversationDecryptMessage, ConversationDecryptMaxMessages+1)
			for i := range r.Messages {
				r.Messages[i] = ConversationDecryptMessage{IVB64: chatFixtureIVB64, CiphertextB64: chatFixtureCt1B64}
			}
		}, "messages"},
		{"short iv", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages[0].IVB64 = "AAECAwQFBgcICQo="
		}, "iv_b64"},
		{"url-safe iv", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages[0].IVB64 = "AAECAwQFBgcICQoL-w=="
		}, "iv_b64"},
		{"empty ciphertext", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages[0].CiphertextB64 = ""
		}, "ciphertext_b64"},
		{"tag-only ciphertext", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages[0].CiphertextB64 = "AAAAAAAAAAAAAAAAAAAAAA==" // 16B: a tag with no message
		}, "ciphertext_b64"},
		{"oversized ciphertext", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.Messages[0].CiphertextB64 = strings.Repeat("Q", 10948) + "==" // 8209B decoded
		}, "ciphertext_b64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := chatValidRequest()
			tc.apply(&r)
			err := r.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name %s, got %q", tc.field, err.Error())
			}
		})
	}
}

func TestConversationReadPermit_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*ConversationReadPermit)
		field string
	}{
		{"malformed account", func(p *ConversationReadPermit) { p.AccountID = "nope" }, "permit.account_id"},
		{"nil org", func(p *ConversationReadPermit) { p.OrgID = "00000000-0000-0000-0000-000000000000" }, "permit.org_id"},
		{"malformed conversation", func(p *ConversationReadPermit) { p.ConversationID = "nope" }, "permit.conversation_id"},
		{"zero dek version", func(p *ConversationReadPermit) { p.DekVersion = 0 }, "permit.dek_version"},
		{"zero issued_at", func(p *ConversationReadPermit) { p.IssuedAt = 0 }, "permit.issued_at"},
		{"unsafe expires_at", func(p *ConversationReadPermit) { p.ExpiresAt = 9007199254740992 }, "permit.expires_at"},
		{"zero key version", func(p *ConversationReadPermit) { p.ServerKeyVersion = 0 }, "permit.server_key_version"},
		{"empty signature", func(p *ConversationReadPermit) { p.Signature = "" }, "permit.signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := chatValidPermit()
			tc.apply(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name %s, got %q", tc.field, err.Error())
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// Room name (0.0.34): the second canonical family
// ────────────────────────────────────────────────────────────────────────

// roomAADGolden / roomPermitCanonicalGolden — the room half of the same two
// canonicals, on the same fixed inputs. Only the domain slot differs, which is
// the point: everything else being identical is what lets one helper serve both
// and what makes the domain the whole of the separation.
const (
	roomAADGolden = "dragpass.room|1|" +
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa|" +
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb|5"
	roomPermitCanonicalGolden = "dragpass.room.read|1|" +
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc|" +
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa|" +
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb|5|" +
		"1700000000|1700000300|1"
)

// TestRoomNameAADCanonical_GoldenVector — the room AAD literal. GR3
// (packages/crypto) builds these bytes on the encrypt side and
// docs/testing/fixtures/chat-rooms-v1.json pins them for ariadne too.
func TestRoomNameAADCanonical_GoldenVector(t *testing.T) {
	got := RoomNameAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion)
	t.Logf("ROOM AAD canonical (golden): %s", got)
	if got != roomAADGolden {
		t.Fatalf("room AAD = %q, want %q", got, roomAADGolden)
	}
	if strings.Count(got, "|") != 4 {
		t.Fatalf("room AAD must have 5 items separated by 4 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("room AAD must not end with a newline")
	}
}

// TestRoomNameReadPermitCanonical_GoldenVector — the 9-item room-name permit
// signing string. ariadne's signer (GR2) asserts the same literal.
func TestRoomNameReadPermitCanonical_GoldenVector(t *testing.T) {
	got := RoomNameReadPermitCanonical(chatValidPermit())
	t.Logf("room-name read-permit canonical (golden): %s", got)
	if got != roomPermitCanonicalGolden {
		t.Fatalf("room permit canonical = %q, want %q", got, roomPermitCanonicalGolden)
	}
	if strings.Count(got, "|") != 8 {
		t.Fatalf("canonical must have 9 items separated by 8 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("canonical must not end with a newline")
	}
}

// TestRoomCanonicals_DomainSeparation — the room strings differ from every
// other domain that could be fed to this key, including the chat pair built
// from the very same (org, conversation, dek_version). A room name and a
// message in one room at one epoch are sealed under one key; the domain is the
// only thing keeping the server from moving a message row into the name column
// and having it render as the room's title.
func TestRoomCanonicals_DomainSeparation(t *testing.T) {
	roomAAD := RoomNameAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion)
	chatAAD := ChatAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion)
	messageAAD := MessageAADCanonical(chatFixtureOrgID, chatFixtureConvID, chatFixtureDekVersion, MessageSchemaVersion, 2000000000)

	if roomAAD == chatAAD {
		t.Fatal("room AAD and chat AAD must not be byte-identical")
	}
	if roomAAD == messageAAD {
		t.Fatal("room AAD and Secure Message AAD must not be byte-identical")
	}
	if !strings.HasPrefix(roomAAD, "dragpass.room|") {
		t.Fatalf("room AAD must start with the room domain, got %q", roomAAD)
	}

	roomPermit := RoomNameReadPermitCanonical(chatValidPermit())
	chatPermit := ConversationReadPermitCanonical(chatValidPermit())
	if roomPermit == chatPermit {
		t.Fatal("room permit canonical and chat permit canonical must not be byte-identical")
	}
	// The domain is also not a prefix of the other, so no verifier that
	// compares prefixes can accept one for the other.
	if strings.HasPrefix(chatPermit, RoomNameReadPermitDomain) ||
		strings.HasPrefix(roomPermit, ChatReadPermitDomain) {
		t.Fatal("neither permit domain may prefix the other")
	}
}

// TestConversationPayloadCanonicals_PairsAreNeverMixed — the helper hands back
// a permit canonical and an AAD from the same family, for every accepted value
// of payload_kind. Verifying a signature in one domain and decrypting in the
// other is the one mistake this action must be unable to make.
func TestConversationPayloadCanonicals_PairsAreNeverMixed(t *testing.T) {
	permit := chatValidPermit()

	cases := []struct {
		kind       string
		wantPermit string
		wantAAD    string
	}{
		{"", chatPermitCanonicalGolden, chatAADGolden},
		{ConversationPayloadKindMessage, chatPermitCanonicalGolden, chatAADGolden},
		{ConversationPayloadKindRoomName, roomPermitCanonicalGolden, roomAADGolden},
	}
	for _, tc := range cases {
		name := tc.kind
		if name == "" {
			name = "omitted"
		}
		t.Run(name, func(t *testing.T) {
			gotPermit, gotAAD := ConversationPayloadCanonicals(tc.kind, permit)
			if gotPermit != tc.wantPermit {
				t.Fatalf("permit canonical = %q, want %q", gotPermit, tc.wantPermit)
			}
			if gotAAD != tc.wantAAD {
				t.Fatalf("aad = %q, want %q", gotAAD, tc.wantAAD)
			}
		})
	}
}

func TestConversationDecrypt_Validate_PayloadKind(t *testing.T) {
	t.Run("omitted is accepted", func(t *testing.T) {
		if err := chatValidRequest().Validate(); err != nil {
			t.Fatalf("omitted payload_kind rejected: %v", err)
		}
	})
	t.Run("message is accepted", func(t *testing.T) {
		r := chatValidRequest()
		r.PayloadKind = ConversationPayloadKindMessage
		if err := r.Validate(); err != nil {
			t.Fatalf("payload_kind=message rejected: %v", err)
		}
	})
	t.Run("room_name with one entry is accepted", func(t *testing.T) {
		r := chatValidRequest()
		r.PayloadKind = ConversationPayloadKindRoomName
		if err := r.Validate(); err != nil {
			t.Fatalf("payload_kind=room_name rejected: %v", err)
		}
	})

	rejects := []struct {
		name  string
		apply func(*ConversationDecryptBatchForAppDisplayRequest)
		field string
	}{
		{"unknown kind", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.PayloadKind = "room"
		}, "payload_kind"},
		{"kind is case sensitive", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.PayloadKind = "Room_Name"
		}, "payload_kind"},
		{"room_name with no entry", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.PayloadKind = ConversationPayloadKindRoomName
			r.Messages = nil
		}, "messages"},
		{"room_name with two entries", func(r *ConversationDecryptBatchForAppDisplayRequest) {
			r.PayloadKind = ConversationPayloadKindRoomName
			r.Messages = append(r.Messages, ConversationDecryptMessage{
				IVB64: chatFixtureIVB64, CiphertextB64: chatFixtureCt1B64,
			})
		}, "messages"},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			r := chatValidRequest()
			tc.apply(&r)
			err := r.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name %s, got %q", tc.field, err.Error())
			}
		})
	}
}
