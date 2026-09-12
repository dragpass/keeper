// actions_message.go — Wire-protocol Action* constants for the Secure Message
// Overlay display path.
//
// Split out of actions_group_dek.go for domain locality, the same way
// actions_credential.go was: these two actions are their own security domain
// (a server-signed display permit bound to a Keeper-minted challenge, a fixed
// message AAD the caller cannot influence, and the single plaintext-returning
// response in the whole protocol), so they keep their own actions_* /
// registry_* fragment pair rather than riding on the Group DEK catalog.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/secure-message-overlay-implementation.md §3.

package proto

const (
	// MessageDisplayPrepare: step one of the two-step reveal. The Keeper
	// validates the structured message context strictly, mints a 32-byte CSPRNG
	// challenge (Base64URL, 43 chars, no padding), and remembers it together
	// with the whole context and `SHA256(IV || ciphertext || tag)` for 30
	// seconds. It decrypts nothing and returns no key material.
	//
	//   Inputs: group_handle, org_id, group_id, dek_version,
	//           message_schema_version (1), token_expires_at,
	//           audit_table_id (string | null), iv_b64(12B), ciphertext_b64
	//   Output: { challenge }
	//
	// The challenge map is process-local and capped at 8 live entries — a ninth
	// concurrent prepare is refused with MESSAGE_DISPLAY_BUSY rather than
	// evicting somebody else's pending reveal. Entries are dropped when they
	// expire, when their group handle is closed, and with the process.
	//
	// The Extension hashes the same payload itself and asks the server for a
	// display permit over this challenge; the server never learns whether the
	// challenge came from a real Keeper. That binding is checked here, in
	// group_decrypt_with_aad_for_app_display.
	ActionMessageDisplayPrepare = "message_display_prepare"

	// GroupDecryptWithAadForAppDisplay: step two. The Keeper verifies the
	// server-signed display permit, consumes the challenge atomically, opens the
	// message under the raw Group DEK behind the opaque handle with an AAD it
	// builds itself, and returns the plaintext.
	//
	//   Inputs: the same nine fields as message_display_prepare, plus `permit`
	//           (challenge, account_id, org_id, group_id, dek_version,
	//           message_schema_version, token_expires_at, audit_table_id,
	//           payload_sha256, issued_at, expires_at, server_key_version,
	//           signature)
	//   Output: { plaintext_b64 }
	//
	// This is the protocol's **only** plaintext-returning response and the first
	// TestNoRawSecretInResponseTypes carve-out since 0.0.11. The approved scope
	// of that exception is exactly this response type; see
	// docs/security/secure-message-overlay-proposed-boundary.md §4 in
	// dragpass-control-plane. Every clipboard action still returns no plaintext.
	//
	// What keeps the exception narrow is that the caller cannot choose what gets
	// opened:
	//
	//  1. The AAD is assembled inside the Keeper from the structured fields as
	//     `dragpass.message|1|<org>|<group>|<dek_version>|<token_expires_at>`.
	//     There is no aad_b64 / domain / canonical field anywhere in the
	//     request, so a drag token (sealed with no AAD) and a credential payload
	//     (sealed under the credential canonical) fail the GCM tag here even
	//     when the caller holds the right handle and names the right context.
	//  2. A server RSA-PSS SHA-256 signature over the 14-item canonical
	//     `dragpass.message.display|1|challenge|account_id|org_id|group_id|
	//     dek_version|1|token_expires_at|audit_table_id_or_-|payload_sha256|
	//     issued_at|expires_at|server_key_version` must verify under the pinned
	//     key of the named version, and every field it covers must equal the
	//     request and the remembered challenge. A missing key version fails
	//     closed. MCP service tokens cannot obtain such a permit.
	//  3. The permit window is narrow and fixed: `issued_at <= now + 5`,
	//     `now < expires_at`, `expires_at - issued_at == 30`, plus the Keeper's
	//     own 30-second challenge lifetime. `now < token_expires_at` is required
	//     with no clock grace and re-checked immediately before the response, so
	//     a late answer cannot display an expired message.
	//  4. The challenge is consumed atomically after the permit verifies and
	//     before the decrypt. A GCM tag failure does not put it back, concurrent
	//     replays leave exactly one winner, and a retry starts from a new
	//     prepare. Another Keeper process holds no such challenge at all.
	//
	// Unknown fields, duplicate JSON keys (the nested permit included), missing
	// fields, and requests over 16 KiB are refused as MESSAGE_INVALID_INPUT
	// before anything is opened.
	ActionGroupDecryptWithAadForAppDisplay = "group_decrypt_with_aad_for_app_display"
)
