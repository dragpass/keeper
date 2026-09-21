// actions_conversation.go — Wire-protocol Action* constant for the DragPass
// 1:1 chat reveal path.
//
// Split out for domain locality, the same way actions_message.go was: this
// action is its own security domain (a server-signed conversation-read-permit,
// a fixed chat AAD the caller cannot influence, and a plaintext-returning
// response), so it keeps its own actions_* / registry_* fragment pair rather
// than riding on the Group DEK catalog.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-1to1-implementation.md §5.

package proto

const (
	// ConversationDecryptBatchForAppDisplay: opens a page of one conversation's
	// messages for browser display. The Keeper verifies the server-signed
	// conversation-read-permit, builds the chat AAD from the permit's structured
	// fields, opens each message under the conversation DEK behind the opaque
	// group handle, and returns the plaintexts parallel to the request batch.
	//
	//   Inputs: group_handle, permit (account_id, org_id, conversation_id,
	//           dek_version, issued_at, expires_at, server_key_version,
	//           signature), org_id, conversation_id, dek_version,
	//           payload_kind? ('message' | 'room_name', default 'message'),
	//           messages: [{ iv_b64(12B), ciphertext_b64(17..8208B) }] (<=200,
	//           exactly 1 when payload_kind is 'room_name')
	//   Output: { plaintext_b64: string[] }  // parallel to messages
	//
	// This is the protocol's second TestNoRawSecretInResponseTypes carve-out
	// (after 0.0.29's group_decrypt_with_aad_for_app_display). Every clipboard
	// action still returns no plaintext. What keeps the exception narrow:
	//
	//  1. The AAD is assembled inside the Keeper from the permit's structured
	//     fields as `dragpass.chat|1|<org>|<conversation>|<dek_version>`. There
	//     is no aad_b64 / domain / canonical field in the request, so a drag
	//     token (no AAD), a Secure Message (`dragpass.message|...`), and a
	//     credential payload (credential canonical) fail the GCM tag here even
	//     when the caller holds the right handle and names the right context.
	//  2. A server RSA-PSS SHA-256 signature over the 9-item canonical
	//     `dragpass.chat.read|1|account_id|org_id|conversation_id|dek_version|
	//     issued_at|expires_at|server_key_version` must verify under the pinned
	//     key of the named version — a missing version fails closed, never
	//     falling back to the active key. The request's (org_id,
	//     conversation_id, dek_version) must equal the permit's.
	//  3. The permit window is narrow and fixed: `issued_at <= now + 5`,
	//     `now < expires_at`, `expires_at - issued_at == 300`.
	//  4. If any message in the batch fails the tag / UTF-8 / AAD, the whole
	//     batch is refused with CHAT_DECRYPT_FAILED and no partial plaintext —
	//     one conversation at one version is one key/AAD family, so a failure is
	//     a tamper or foreign-ciphertext signal.
	//
	// Named group rooms (0.0.34) reuse this action rather than adding one.
	// `payload_kind` is the only thing the caller may say about binding, and it
	// is an enum of two values, not a string the caller composes:
	//
	//   'message'   (default, and what an omitted field means) → permit
	//               canonical `dragpass.chat.read|1|...`, AAD `dragpass.chat|1|...`
	//   'room_name' → permit canonical `dragpass.room.read|1|...`, AAD
	//               `dragpass.room|1|...`, and exactly one entry in messages,
	//               since a room has one name
	//
	// The pair is chosen together, so a message permit presented for a
	// room_name request fails signature verification and a room name fed to a
	// message request fails the GCM tag. Choosing the canonical is the binding
	// check; there is no separate one to forget. The room-name branch returns
	// its plaintext through the same plaintext_b64 and adds no carve-out entry.
	//
	// Unknown fields, duplicate JSON keys (the nested permit included), missing
	// fields, an unknown payload_kind, a room_name batch that is not exactly one
	// entry, and requests over 2 MiB are refused as CHAT_INVALID_INPUT before
	// anything is opened.
	//
	// There is no per-message challenge and no prepare step: opening the group
	// handle from a wrapped grant is itself the key-possession proof.
	ActionConversationDecryptBatchForAppDisplay = "conversation_decrypt_batch_for_app_display"
)
