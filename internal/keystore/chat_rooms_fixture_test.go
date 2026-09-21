// chat_rooms_fixture_test.go — the cross-repo named-group-room vector (GR0).
//
// testdata/chat-rooms-v1.json is a copy of dragpass-control-plane
// docs/testing/fixtures/chat-rooms-v1.json, read by ariadne and the TypeScript
// side from the same bytes. Its job is to pin the things three independent
// implementations have to agree on for a room to be readable at all: the
// dragpass.room AAD, the dragpass.room.read permit canonical, and the tag those
// produce. A mismatch is silent — nobody errors, the room name simply never
// opens again.
//
// A fixture is a vector, not a round trip. Every assertion here feeds fixed
// bytes to one function and compares the answer; none of it shows that a room
// can be created, renamed, or read end to end. That claim belongs to the GR7
// e2e run against a real Keeper and a real ariadne, and this file passing is
// not evidence for it.
//
// Field names must stay exactly as the contract lists them
// (dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-grouproom-implementation.md §5 / §9);
// the other consumers read the same keys.

package keystore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type chatRoomsFixture struct {
	FixtureVersion int    `json:"fixture_version"`
	TestOnly       bool   `json:"test_only"`
	OrgID          string `json:"org_id"`
	ConversationID string `json:"conversation_id"`
	AccountID      string `json:"account_id"`
	DekVersion     int    `json:"dek_version"`

	KeyHex string `json:"key_hex"`
	IVHex  string `json:"iv_hex"`
	IVB64  string `json:"iv_b64"`

	RoomNameUTF8       string `json:"room_name_utf8"`
	RoomNameHex        string `json:"room_name_hex"`
	RoomNameB64        string `json:"room_name_b64"`
	RoomNameCodePoints int    `json:"room_name_code_points"`
	RoomNameUTF8Bytes  int    `json:"room_name_utf8_bytes"`

	RoomAADUTF8 string `json:"room_aad_utf8"`
	RoomAADHex  string `json:"room_aad_hex"`

	RoomNameCiphertextHex      string `json:"room_name_ciphertext_hex"`
	RoomNameTagHex             string `json:"room_name_tag_hex"`
	RoomNameCiphertextTagB64   string `json:"room_name_ciphertext_and_tag_b64"`
	RoomReadPermitCanonical    string `json:"room_read_permit_canonical_utf8"`
	RoomReadPermitCanonHex     string `json:"room_read_permit_canonical_hex"`
	RoomReadPermitSignatureB64 string `json:"room_read_permit_signature_b64"`

	RoomReadPermit struct {
		AccountID        string `json:"account_id"`
		OrgID            string `json:"org_id"`
		ConversationID   string `json:"conversation_id"`
		DekVersion       int    `json:"dek_version"`
		IssuedAt         int64  `json:"issued_at"`
		ExpiresAt        int64  `json:"expires_at"`
		ServerKeyVersion uint   `json:"server_key_version"`
	} `json:"room_read_permit"`

	ServerPublicKeyPEM string `json:"server_public_key_pem"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`

	NegativeChatDomain struct {
		ChatAADUTF8                string `json:"chat_aad_utf8"`
		ChatAADHex                 string `json:"chat_aad_hex"`
		CiphertextHex              string `json:"ciphertext_hex"`
		TagHex                     string `json:"tag_hex"`
		CiphertextTagB64           string `json:"ciphertext_and_tag_b64"`
		ChatReadPermitCanonical    string `json:"chat_read_permit_canonical_utf8"`
		ChatReadPermitSignatureB64 string `json:"chat_read_permit_signature_b64"`
	} `json:"negative_chat_domain"`
}

func loadChatRoomsFixture(t *testing.T) chatRoomsFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/chat-rooms-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture chatRoomsFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.FixtureVersion != 1 || !fixture.TestOnly {
		t.Fatalf("fixture header = version %d test_only %t, want 1/true",
			fixture.FixtureVersion, fixture.TestOnly)
	}
	return fixture
}

func (f chatRoomsFixture) permit(t *testing.T) proto.ConversationReadPermit {
	t.Helper()
	p := f.RoomReadPermit
	// The permit block and the top-level ids describe one conversation. If a
	// hand edit ever splits them the vectors below would silently stop
	// describing the same thing.
	if p.OrgID != f.OrgID || p.ConversationID != f.ConversationID ||
		p.AccountID != f.AccountID || p.DekVersion != f.DekVersion {
		t.Fatal("room_read_permit does not describe the fixture's own conversation")
	}
	if p.ExpiresAt-p.IssuedAt != proto.ChatReadPermitTTLSeconds {
		t.Fatalf("permit window = %ds, want %ds",
			p.ExpiresAt-p.IssuedAt, proto.ChatReadPermitTTLSeconds)
	}
	return proto.ConversationReadPermit{
		AccountID:        p.AccountID,
		OrgID:            p.OrgID,
		ConversationID:   p.ConversationID,
		DekVersion:       p.DekVersion,
		IssuedAt:         p.IssuedAt,
		ExpiresAt:        p.ExpiresAt,
		ServerKeyVersion: p.ServerKeyVersion,
		Signature:        f.RoomReadPermitSignatureB64,
	}
}

func decodeHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return b
}

// The UTF-8, hex, and Base64 forms of every string have to be the same bytes,
// since each consumer reads whichever one suits it.
func TestChatRoomsFixture_EncodingsAgree(t *testing.T) {
	f := loadChatRoomsFixture(t)

	for _, pair := range []struct {
		name string
		text string
		hex  string
	}{
		{"room_name", f.RoomNameUTF8, f.RoomNameHex},
		{"room_aad", f.RoomAADUTF8, f.RoomAADHex},
		{"room_read_permit_canonical", f.RoomReadPermitCanonical, f.RoomReadPermitCanonHex},
		{"negative chat_aad", f.NegativeChatDomain.ChatAADUTF8, f.NegativeChatDomain.ChatAADHex},
	} {
		if got := hex.EncodeToString([]byte(pair.text)); got != pair.hex {
			t.Errorf("%s hex = %s, want %s", pair.name, got, pair.hex)
		}
	}
	if got := base64.StdEncoding.EncodeToString([]byte(f.RoomNameUTF8)); got != f.RoomNameB64 {
		t.Errorf("room_name_b64 = %s, want %s", got, f.RoomNameB64)
	}
	if got := base64.StdEncoding.EncodeToString(decodeHex(t, "iv_hex", f.IVHex)); got != f.IVB64 {
		t.Errorf("iv_b64 = %s, want %s", got, f.IVB64)
	}
	if got := base64.StdEncoding.EncodeToString([]byte(f.ServerPublicKeyPEM)); got != f.ServerPublicKeyB64 {
		t.Error("server_public_key_b64 does not decode to its PEM")
	}

	// The two room-name length rules (D5) are different counts of one string.
	if got := utf8.RuneCountInString(f.RoomNameUTF8); got != f.RoomNameCodePoints {
		t.Errorf("room_name_code_points = %d, want %d", got, f.RoomNameCodePoints)
	}
	if got := len(f.RoomNameUTF8); got != f.RoomNameUTF8Bytes {
		t.Errorf("room_name_utf8_bytes = %d, want %d", got, f.RoomNameUTF8Bytes)
	}
	if f.RoomNameCodePoints == f.RoomNameUTF8Bytes {
		t.Error("the fixture room name must be non-ASCII, or it cannot tell the two D5 counts apart")
	}
}

// The two canonical builders reproduce the fixture's bytes exactly.
func TestChatRoomsFixture_Canonicals(t *testing.T) {
	f := loadChatRoomsFixture(t)

	if got := proto.RoomNameAADCanonical(f.OrgID, f.ConversationID, f.DekVersion); got != f.RoomAADUTF8 {
		t.Fatalf("room AAD = %q, want %q", got, f.RoomAADUTF8)
	}
	if got := proto.RoomNameReadPermitCanonical(f.permit(t)); got != f.RoomReadPermitCanonical {
		t.Fatalf("room permit canonical = %q, want %q", got, f.RoomReadPermitCanonical)
	}
	// The negative half is a canonical too, and it has to be the one ariadne's
	// 1:1 signer already produces — otherwise "these are different bytes" would
	// be a comparison against something nobody builds.
	neg := f.NegativeChatDomain
	if got := proto.ChatAADCanonical(f.OrgID, f.ConversationID, f.DekVersion); got != neg.ChatAADUTF8 {
		t.Fatalf("chat AAD = %q, want %q", got, neg.ChatAADUTF8)
	}
	if got := proto.ConversationReadPermitCanonical(f.permit(t)); got != neg.ChatReadPermitCanonical {
		t.Fatalf("chat permit canonical = %q, want %q", got, neg.ChatReadPermitCanonical)
	}
	if f.RoomAADUTF8 == neg.ChatAADUTF8 {
		t.Fatal("the room AAD and the chat AAD for the same conversation must be different bytes")
	}
	if f.RoomReadPermitCanonical == neg.ChatReadPermitCanonical {
		t.Fatal("the two permit canonicals for the same permit must be different bytes")
	}
}

// The room name opens under the room AAD, and does not open under the chat one.
func TestChatRoomsFixture_RoomNameRoundtripVector(t *testing.T) {
	f := loadChatRoomsFixture(t)
	key := decodeHex(t, "key_hex", f.KeyHex)
	iv := decodeHex(t, "iv_hex", f.IVHex)
	sealed := append(decodeHex(t, "room_name_ciphertext_hex", f.RoomNameCiphertextHex),
		decodeHex(t, "room_name_tag_hex", f.RoomNameTagHex)...)

	if got := base64.StdEncoding.EncodeToString(sealed); got != f.RoomNameCiphertextTagB64 {
		t.Fatalf("room_name_ciphertext_and_tag_b64 = %s, want %s", got, f.RoomNameCiphertextTagB64)
	}

	roomAAD := []byte(proto.RoomNameAADCanonical(f.OrgID, f.ConversationID, f.DekVersion))
	plaintext, err := handlers.AESGCMOpenWithAAD(key, iv, sealed, roomAAD)
	if err != nil {
		t.Fatalf("room name does not open under the room AAD: %v", err)
	}
	if string(plaintext) != f.RoomNameUTF8 {
		t.Fatalf("room name = %q, want %q", string(plaintext), f.RoomNameUTF8)
	}

	chatAAD := []byte(proto.ChatAADCanonical(f.OrgID, f.ConversationID, f.DekVersion))
	if _, err := handlers.AESGCMOpenWithAAD(key, iv, sealed, chatAAD); err == nil {
		t.Fatal("the room name opened under the chat AAD — the domains are not separated")
	}
}

// The negative vector: same plaintext, key, IV, and conversation, sealed under
// the chat domain. AES-GCM leaves the ciphertext bytes identical and changes
// only the tag, so this pair is the sharpest statement of what the domain
// actually buys.
func TestChatRoomsFixture_ChatDomainNegativeVector(t *testing.T) {
	f := loadChatRoomsFixture(t)
	neg := f.NegativeChatDomain
	key := decodeHex(t, "key_hex", f.KeyHex)
	iv := decodeHex(t, "iv_hex", f.IVHex)
	sealed := append(decodeHex(t, "negative ciphertext_hex", neg.CiphertextHex),
		decodeHex(t, "negative tag_hex", neg.TagHex)...)

	if got := base64.StdEncoding.EncodeToString(sealed); got != neg.CiphertextTagB64 {
		t.Fatalf("negative ciphertext_and_tag_b64 = %s, want %s", got, neg.CiphertextTagB64)
	}
	if neg.CiphertextHex != f.RoomNameCiphertextHex {
		t.Fatal("the negative vector must share the room vector's ciphertext bytes — " +
			"if it does not, it is testing a different plaintext, key, or IV rather than the AAD")
	}
	if neg.TagHex == f.RoomNameTagHex {
		t.Fatal("the two tags are identical — the AAD is not reaching the GCM tag")
	}

	chatAAD := []byte(proto.ChatAADCanonical(f.OrgID, f.ConversationID, f.DekVersion))
	plaintext, err := handlers.AESGCMOpenWithAAD(key, iv, sealed, chatAAD)
	if err != nil {
		t.Fatalf("the negative vector does not open under its own chat AAD: %v", err)
	}
	if string(plaintext) != f.RoomNameUTF8 {
		t.Fatalf("negative plaintext = %q, want %q", string(plaintext), f.RoomNameUTF8)
	}

	roomAAD := []byte(proto.RoomNameAADCanonical(f.OrgID, f.ConversationID, f.DekVersion))
	if _, err := handlers.AESGCMOpenWithAAD(key, iv, sealed, roomAAD); err == nil {
		t.Fatal("a chat-sealed ciphertext opened under the room AAD — the domains are not separated")
	}
}

// The permit signature vector. RSA-PSS is randomized, so the fixture pins a
// signature to verify, not one to reproduce: what has to match across repos is
// the canonical the signature covers.
func TestChatRoomsFixture_RoomReadPermitSignature(t *testing.T) {
	f := loadChatRoomsFixture(t)
	neg := f.NegativeChatDomain

	pub, err := crypto.ParsePublicKey(f.ServerPublicKeyPEM)
	if err != nil {
		t.Fatalf("server public key does not parse: %v", err)
	}
	roomSig, err := base64.StdEncoding.DecodeString(f.RoomReadPermitSignatureB64)
	if err != nil {
		t.Fatalf("decode room permit signature: %v", err)
	}
	chatSig, err := base64.StdEncoding.DecodeString(neg.ChatReadPermitSignatureB64)
	if err != nil {
		t.Fatalf("decode chat permit signature: %v", err)
	}

	permit := f.permit(t)
	roomCanonical := proto.RoomNameReadPermitCanonical(permit)
	chatCanonical := proto.ConversationReadPermitCanonical(permit)

	if err := crypto.VerifySignature(pub, roomCanonical, roomSig); err != nil {
		t.Fatalf("room permit signature does not verify over the room canonical: %v", err)
	}
	if err := crypto.VerifySignature(pub, chatCanonical, chatSig); err != nil {
		t.Fatalf("chat permit signature does not verify over the chat canonical: %v", err)
	}

	// The crossed pairs are the whole reason there are two domains: a permit
	// issued for reading a room's name must not authorize reading its messages,
	// and the signature is the only place that distinction exists.
	if err := crypto.VerifySignature(pub, chatCanonical, roomSig); err == nil {
		t.Fatal("the room permit verified as a message permit")
	}
	if err := crypto.VerifySignature(pub, roomCanonical, chatSig); err == nil {
		t.Fatal("the message permit verified as a room permit")
	}
}

// What the handler would pick for each payload_kind, checked against the
// fixture rather than against itself.
func TestChatRoomsFixture_PayloadKindSelectsTheRoomPair(t *testing.T) {
	f := loadChatRoomsFixture(t)
	permit := f.permit(t)

	permitCanonical, aad := proto.ConversationPayloadCanonicals(
		proto.ConversationPayloadKindRoomName, permit)
	if permitCanonical != f.RoomReadPermitCanonical {
		t.Fatalf("room_name permit canonical = %q, want %q", permitCanonical, f.RoomReadPermitCanonical)
	}
	if aad != f.RoomAADUTF8 {
		t.Fatalf("room_name aad = %q, want %q", aad, f.RoomAADUTF8)
	}

	permitCanonical, aad = proto.ConversationPayloadCanonicals(
		proto.ConversationPayloadKindMessage, permit)
	if permitCanonical != f.NegativeChatDomain.ChatReadPermitCanonical {
		t.Fatalf("message permit canonical = %q, want %q",
			permitCanonical, f.NegativeChatDomain.ChatReadPermitCanonical)
	}
	if aad != f.NegativeChatDomain.ChatAADUTF8 {
		t.Fatalf("message aad = %q, want %q", aad, f.NegativeChatDomain.ChatAADUTF8)
	}
}
