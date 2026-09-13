// conversation_decrypt_test.go — the DragPass 1:1 chat reveal, happy path and
// at every refusal.
//
// The golden vector (key, IVs, chat AAD, ciphertexts) is a CC0 AES-256-GCM
// vector: key 0x20..0x3f, chat AAD dragpass.chat|1|<org>|<conv>|5. The two
// foreign ciphertexts are the same plaintext under the same key with no AAD and
// with the Secure Message AAD; both must fail here. That is the whole argument
// for why a plaintext-returning action does not widen into "the app can decrypt
// anything the org can" — a ciphertext not sealed under the chat AAD does not
// open.
//
// The RSA verifier double (msgTestVerifier), the injected clock (msgTestClock),
// the test server key (msgTestServerKey), and msgServerKeyVersion are shared
// with message_display_test.go (same package).

package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	chatKeyHex   = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	chatIV1B64   = "AAECAwQFBgcICQoL"
	chatIV2B64   = "EBESExQVFhcYGRob"
	chatCt1B64   = "GCA8wBpUmJ+cmqGnUlMzWWADiAMPMcl/QQeov7RajOdKoFQy06tZ+Ufw"
	chatCt2B64   = "ZK+edR8iYfVTO09FoOjNRB7+tT9QKHNlzzAyUfBRaMYq7urVHpsyqm4g"
	chatPt1B64   = "RHJhZ1Bhc3MgY2hhdCBtZXNzYWdlIG9uZQo="
	chatPt2B64   = "RHJhZ1Bhc3MgY2hhdCBtZXNzYWdlIHR3bwo="
	chatPt1Plain = "DragPass chat message one\n"

	// Same key + IV as ct1 but sealed under no AAD / the Secure Message AAD —
	// foreign to the chat AAD, so they must fail the tag in the chat action.
	chatForeignNonAADB64 = "GCA8wBpUmJ+cmqGnUlMzWWADiAMPMcl/QQcgJAsuO7jg0fyaWidP2f+K"
	chatForeignMsgAADB64 = "GCA8wBpUmJ+cmqGnUlMzWWADiAMPMcl/QQckxapwqX+mpx6pdCwhZTUT"

	chatOrgID      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	chatConvID     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	chatAccountID  = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	chatOtherUUID  = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	chatDekVersion = 5

	// chatNowUnix — a fixed "now" equal to the permit's issued_at, comfortably
	// inside the 300-second window.
	chatNowUnix = 1700000000
)

// ────────────────────────────────────────────────────────────────────────
// Harness
// ────────────────────────────────────────────────────────────────────────

type chatFixture struct {
	deps   Deps
	log    *logger.MemoryLogger
	clock  *msgTestClock
	handle string
	key    *rsa.PrivateKey
}

func newChatFixture(t *testing.T) *chatFixture {
	t.Helper()
	deps, log, _ := newTestDeps(t)
	clock := &msgTestClock{unix: chatNowUnix}
	deps.Clock = clock.now
	key := msgTestServerKey()
	deps.ServerKeyVerifier = msgTestVerifier{version: msgServerKeyVersion, public: &key.PublicKey}
	f := &chatFixture{deps: deps, log: log, clock: clock, key: key}
	f.handle = f.openHandle(t)
	return f
}

func (f *chatFixture) openHandle(t *testing.T) string {
	t.Helper()
	raw, err := hex.DecodeString(chatKeyHex)
	if err != nil {
		t.Fatalf("decode fixture key: %v", err)
	}
	handle, _, err := f.deps.GroupSessions.Open(raw)
	if err != nil {
		t.Fatalf("open group session: %v", err)
	}
	t.Cleanup(func() { f.deps.GroupSessions.Close(handle) })
	return handle
}

// request returns the two-message batch for the golden vector, minus the permit.
func (f *chatFixture) request() proto.ConversationDecryptBatchForAppDisplayRequest {
	return proto.ConversationDecryptBatchForAppDisplayRequest{
		GroupHandle:    f.handle,
		OrgID:          chatOrgID,
		ConversationID: chatConvID,
		DekVersion:     chatDekVersion,
		Messages: []proto.ConversationDecryptMessage{
			{IVB64: chatIV1B64, CiphertextB64: chatCt1B64},
			{IVB64: chatIV2B64, CiphertextB64: chatCt2B64},
		},
	}
}

func (f *chatFixture) unsignedPermit(r proto.ConversationDecryptBatchForAppDisplayRequest) proto.ConversationReadPermit {
	now := f.clock.now().Unix()
	return proto.ConversationReadPermit{
		AccountID:        chatAccountID,
		OrgID:            r.OrgID,
		ConversationID:   r.ConversationID,
		DekVersion:       r.DekVersion,
		IssuedAt:         now,
		ExpiresAt:        now + proto.ChatReadPermitTTLSeconds,
		ServerKeyVersion: msgServerKeyVersion,
	}
}

func (f *chatFixture) sign(t *testing.T, p proto.ConversationReadPermit) proto.ConversationReadPermit {
	t.Helper()
	sig, err := crypto.SignData(f.key, proto.ConversationReadPermitCanonical(p))
	if err != nil {
		t.Fatalf("sign permit: %v", err)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}

func (f *chatFixture) signedPermit(t *testing.T, r proto.ConversationDecryptBatchForAppDisplayRequest) proto.ConversationReadPermit {
	t.Helper()
	return f.sign(t, f.unsignedPermit(r))
}

// authorized returns a request with a correctly signed permit — the flow that
// is known to work, so the tests that break one thing start from it.
func (f *chatFixture) authorized(t *testing.T) proto.ConversationDecryptBatchForAppDisplayRequest {
	t.Helper()
	req := f.request()
	req.Permit = f.signedPermit(t, req)
	return req
}

func (f *chatFixture) display(t *testing.T, r proto.ConversationDecryptBatchForAppDisplayRequest) proto.BaseResponse {
	t.Helper()
	return HandleConversationDecryptBatchForAppDisplay(f.deps, chatMarshal(t, r))
}

func (f *chatFixture) displayRaw(payload json.RawMessage) proto.BaseResponse {
	return HandleConversationDecryptBatchForAppDisplay(f.deps, payload)
}

func chatMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

func assertChatFailure(t *testing.T, resp proto.BaseResponse, wantCode string) {
	t.Helper()
	if resp.Success {
		t.Fatalf("expected failure %s, got success", wantCode)
	}
	if resp.ErrorCode != wantCode {
		t.Fatalf("error_code = %q, want %q (message %q)", resp.ErrorCode, wantCode, resp.Error)
	}
	if resp.Data != nil {
		t.Fatalf("failure must carry no data, got %+v", resp.Data)
	}
}

func assertChatPlaintexts(t *testing.T, resp proto.BaseResponse, want ...string) {
	t.Helper()
	if !resp.Success {
		t.Fatalf("expected success, got %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.ConversationDecryptBatchForAppDisplayResponseData)
	if !ok {
		t.Fatalf("display data type = %T", resp.Data)
	}
	if len(data.PlaintextB64) != len(want) {
		t.Fatalf("plaintext_b64 length = %d, want %d", len(data.PlaintextB64), len(want))
	}
	for i := range want {
		if data.PlaintextB64[i] != want[i] {
			t.Fatalf("plaintext_b64[%d] = %q, want %q", i, data.PlaintextB64[i], want[i])
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// Happy path
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_HappyPath_BatchInOrder(t *testing.T) {
	f := newChatFixture(t)
	resp := f.display(t, f.authorized(t))
	assertChatPlaintexts(t, resp, chatPt1B64, chatPt2B64)
}

func TestConversationDecrypt_HappyPath_SingleMessage(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	req.Messages = req.Messages[:1]
	req.Permit = f.signedPermit(t, req)
	resp := f.display(t, req)
	assertChatPlaintexts(t, resp, chatPt1B64)
}

func TestConversationDecrypt_PlaintextNeverLogged(t *testing.T) {
	f := newChatFixture(t)
	resp := f.display(t, f.authorized(t))
	assertChatPlaintexts(t, resp, chatPt1B64, chatPt2B64)
	if f.log.Contains(chatPt1Plain) {
		t.Fatal("plaintext leaked into the log buffer")
	}
	if f.log.Contains(chatPt1B64) {
		t.Fatal("plaintext (base64) leaked into the log buffer")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Binding: request must match the permit
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_BindingMismatch_NotAuthorized(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*proto.ConversationDecryptBatchForAppDisplayRequest)
	}{
		{"org_id", func(r *proto.ConversationDecryptBatchForAppDisplayRequest) { r.OrgID = chatOtherUUID }},
		{"conversation_id", func(r *proto.ConversationDecryptBatchForAppDisplayRequest) { r.ConversationID = chatOtherUUID }},
		{"dek_version", func(r *proto.ConversationDecryptBatchForAppDisplayRequest) { r.DekVersion = chatDekVersion + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatFixture(t)
			req := f.authorized(t) // permit signed for the original values
			tc.apply(&req)         // now the request disagrees with the permit
			assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// Signature / key version
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_TamperedSignature_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.authorized(t)
	// Flip the first signature byte after decoding, keeping it valid Base64.
	sig, err := base64.StdEncoding.DecodeString(req.Permit.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig[0] ^= 0xff
	req.Permit.Signature = base64.StdEncoding.EncodeToString(sig)
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

func TestConversationDecrypt_UnknownKeyVersion_FailsClosed(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	permit := f.unsignedPermit(req)
	permit.ServerKeyVersion = msgServerKeyVersion + 1 // not pinned by the verifier double
	req.Permit = f.sign(t, permit)                    // canonical includes version 2, so the signature is well-formed
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

// ────────────────────────────────────────────────────────────────────────
// Window
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_IssuedAtTooFarFuture_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	permit := f.unsignedPermit(req)
	permit.IssuedAt = chatNowUnix + 10 // skew allows only +5
	permit.ExpiresAt = permit.IssuedAt + proto.ChatReadPermitTTLSeconds
	req.Permit = f.sign(t, permit)
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

func TestConversationDecrypt_WindowNot300_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	permit := f.unsignedPermit(req)
	permit.ExpiresAt = permit.IssuedAt + 299 // not exactly 300
	req.Permit = f.sign(t, permit)
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

func TestConversationDecrypt_Expired_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.authorized(t)
	f.clock.advance(proto.ChatReadPermitTTLSeconds + 1) // now >= expires_at
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

// ────────────────────────────────────────────────────────────────────────
// Group handle possession
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_ClosedHandle_NotAuthorized(t *testing.T) {
	f := newChatFixture(t)
	req := f.authorized(t)
	f.deps.GroupSessions.Close(f.handle)
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodePermitNotAuthorized)
}

// ────────────────────────────────────────────────────────────────────────
// Domain separation: a foreign ciphertext refuses the whole batch
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_ForeignCiphertext_DecryptFailedNoPartial(t *testing.T) {
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
			req := f.request()
			// A good message first, then the foreign one: even a partial success
			// on message 0 must not leak — the whole batch is refused.
			req.Messages = []proto.ConversationDecryptMessage{
				{IVB64: chatIV1B64, CiphertextB64: chatCt1B64},
				{IVB64: chatIV1B64, CiphertextB64: tc.foreign},
			}
			req.Permit = f.signedPermit(t, req)
			resp := f.display(t, req)
			assertChatFailure(t, resp, proto.ChatErrorCodeDecryptFailed)
			if f.log.Contains(chatPt1Plain) || f.log.Contains(chatPt1B64) {
				t.Fatal("partial plaintext leaked into the log buffer")
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// Input validation
// ────────────────────────────────────────────────────────────────────────

func TestConversationDecrypt_BatchOverCap_InvalidInput(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	req.Messages = make([]proto.ConversationDecryptMessage, proto.ConversationDecryptMaxMessages+1)
	for i := range req.Messages {
		req.Messages[i] = proto.ConversationDecryptMessage{IVB64: chatIV1B64, CiphertextB64: chatCt1B64}
	}
	req.Permit = f.signedPermit(t, req)
	assertChatFailure(t, f.display(t, req), proto.ChatErrorCodeInvalidInput)
}

func TestConversationDecrypt_Oversize_InvalidInput(t *testing.T) {
	f := newChatFixture(t)
	req := f.request()
	// 200 messages (within the count cap) but each ciphertext is ~10.5 KB of
	// valid Base64, so the request as a whole clears 2 MiB — only the size guard
	// can reject it, which is the point.
	big := strings.Repeat("Q", 10500) // 10500 % 4 == 0 → valid Base64
	req.Messages = make([]proto.ConversationDecryptMessage, proto.ConversationDecryptMaxMessages)
	for i := range req.Messages {
		req.Messages[i] = proto.ConversationDecryptMessage{IVB64: chatIV1B64, CiphertextB64: big}
	}
	req.Permit = f.signedPermit(t, req)
	payload := chatMarshal(t, req)
	if len(payload) <= proto.ConversationDecryptMaxRequestBytes {
		t.Fatalf("test payload is %d bytes, needs to exceed %d", len(payload), proto.ConversationDecryptMaxRequestBytes)
	}
	assertChatFailure(t, f.displayRaw(payload), proto.ChatErrorCodeInvalidInput)
}

func TestConversationDecrypt_UnknownKey_InvalidInput(t *testing.T) {
	f := newChatFixture(t)
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(chatMarshal(t, f.authorized(t)), &object); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	object["bogus"] = json.RawMessage(`1`)
	assertChatFailure(t, f.displayRaw(chatMarshal(t, object)), proto.ChatErrorCodeInvalidInput)
}

func TestConversationDecrypt_DuplicateKey_InvalidInput(t *testing.T) {
	f := newChatFixture(t)
	payload := string(chatMarshal(t, f.authorized(t)))

	t.Run("top-level", func(t *testing.T) {
		dup := "{" + `"dek_version":5,` + payload[1:] // duplicate top-level dek_version
		assertChatFailure(t, f.displayRaw(json.RawMessage(dup)), proto.ChatErrorCodeInvalidInput)
	})
	t.Run("nested permit", func(t *testing.T) {
		dup := strings.Replace(payload, `"permit":{`, `"permit":{"dek_version":5,`, 1)
		if dup == payload {
			t.Fatal("failed to inject a duplicate permit key")
		}
		assertChatFailure(t, f.displayRaw(json.RawMessage(dup)), proto.ChatErrorCodeInvalidInput)
	})
}

func TestConversationDecrypt_MissingKey_InvalidInput(t *testing.T) {
	f := newChatFixture(t)

	t.Run("top-level", func(t *testing.T) {
		object := map[string]json.RawMessage{}
		if err := json.Unmarshal(chatMarshal(t, f.authorized(t)), &object); err != nil {
			t.Fatalf("unmarshal to map: %v", err)
		}
		delete(object, "conversation_id")
		assertChatFailure(t, f.displayRaw(chatMarshal(t, object)), proto.ChatErrorCodeInvalidInput)
	})
	t.Run("nested permit", func(t *testing.T) {
		object := map[string]json.RawMessage{}
		if err := json.Unmarshal(chatMarshal(t, f.authorized(t)), &object); err != nil {
			t.Fatalf("unmarshal to map: %v", err)
		}
		permit := map[string]json.RawMessage{}
		if err := json.Unmarshal(object["permit"], &permit); err != nil {
			t.Fatalf("unmarshal permit: %v", err)
		}
		delete(permit, "signature")
		object["permit"] = chatMarshal(t, permit)
		assertChatFailure(t, f.displayRaw(chatMarshal(t, object)), proto.ChatErrorCodeInvalidInput)
	})
}
