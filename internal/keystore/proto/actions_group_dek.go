// Group DEK protocol actions.

package proto

const (
	// DEKRewrapWithOldKeyToSelf: the recovery rewrap with no caller-chosen
	// target. The Keeper wraps to its own active account key, and only after
	// save_session_code promoted the recovered keypair; a caller cannot use
	// the recovered old key to wrap grants to a key of its choosing.
	//   Inputs: challenge_token + signature + recovery_handle +
	//           encrypted_group_dek
	//   Output: new_encrypted_group_dek
	ActionDEKRewrapWithOldKeyToSelf = "dek_rewrap_with_old_key_to_self"

	// Group DEK opaque handle.
	//
	// GroupSessionOpen:   takes wrapped_group_dek and (with the active
	//                     Keychain priv key) RSA-OAEP-unwraps to keep the
	//                     raw 32B in Keeper memguard. Returns a 32B random
	//                     handle ID (Base64) and expires_at_ms (Unix ms).
	//                     The Extension never sees the raw bytes.
	// GroupSessionClose:  destroys and removes the handle. Idempotent
	//                     (missing handles are OK).
	//
	// Subsequent aes_* actions (4 of them) take group_handle instead of
	// group_dek_b64 and run AES-GCM against the same key material. The raw
	// Group DEK Base64 does not live in the Extension JS heap.
	//
	ActionGroupSessionOpen  = "group_session_open"
	ActionGroupSessionClose = "group_session_close"

	// Closes surfaces where admin actions (adminCreateOrg / adminCreateGroup
	// / adminInviteMember / adminRotateDek) had the raw 32B Group DEK
	// living in the Extension JS heap. Replaced by Keeper composite actions.
	//
	// GroupDEKGenerateAndOpen: generate a new 32B Group DEK + register it
	//                          with GroupSessionStore + RSA-OAEP-wrap it
	//                          with my own public key. Response contains
	//                          only the handle + wrappedForMe — raw is
	//                          never in the response.
	// DEKRewrapForMember:      unwrap my wrapped Group DEK with the
	//                          Keychain priv → wrap with the peer's public
	//                          key. The raw briefly lives only in Keeper
	//                          memory; the response contains only the new
	//                          wrap.
	// DEKUnwrapAndRewrapForMany: the multi-recipient variant of
	//                          DEKRewrapForMember. Unwrap my wrapped Group DEK
	//                          once with the Keychain priv, then RSA-OAEP wrap
	//                          it to each recipient public key in the list. The
	//                          raw is unwrapped once and lives only in Keeper
	//                          memory; the response carries only the parallel
	//                          list of new wraps. Used by adminRotateDek to
	//                          wrap the OLD Group DEK to every member + the org
	//                          archive key without the raw ever entering the
	//                          Extension JS heap.
	ActionGroupDEKGenerateAndOpen   = "group_dek_generate_and_open"
	ActionDEKRewrapForMember        = "dek_rewrap_for_member"
	ActionDEKUnwrapAndRewrapForMany = "dek_unwrap_and_rewrap_for_many"

	// GroupDecryptToClipboard: action where the Keeper unwraps a drag /
	// audit token (raw Group DEK direct encryption) and writes the
	// plaintext directly to the OS clipboard.
	//   Inputs: group_handle, iv_b64(12B), ciphertext_b64,
	//           clipboard_ttl_ms
	//   Output: {copied, clipboard_ttl_ms}
	ActionGroupDecryptToClipboard = "group_decrypt_to_clipboard"

	// GroupEncrypt: the encrypt-direction mirror of GroupDecryptToClipboard.
	// AES-GCM-seals plaintext directly under the raw Group DEK behind the
	// opaque handle (no Item DEK indirection) and returns {iv_b64,
	// ciphertext_b64}. First step of moving drag encryption off client-side
	// AES-GCM onto Keeper handles.
	//   Inputs: group_handle, plaintext_b64
	//   Output: {iv_b64(12B), ciphertext_b64}
	// The plaintext lives only in the request and briefly in Keeper memory
	// (zeroized after sealing); it never appears in the response or logs. The
	// raw Group DEK never crosses IPC.
	ActionGroupEncrypt = "group_encrypt"

	// GroupEncryptWithAAD: AAD-binding variant of GroupEncrypt. AES-GCM-seals
	// plaintext under the raw Group DEK behind the opaque handle with a caller-
	// supplied AAD bound into the GCM tag. The AAD carries the sealed payload's
	// canonical context (scope_id|entry_id|payload_kind|schema_version|dek_version)
	// so a ciphertext cannot be swapped to a different context without failing to
	// open. AAD is required — a nil/empty AAD is what GroupEncrypt already covers.
	//   Inputs: group_handle, plaintext_b64, aad_b64
	//   Output: {iv_b64(12B), ciphertext_b64}
	// The plaintext lives only in the request and briefly in Keeper memory
	// (zeroized after sealing); it never appears in the response or logs. The AAD
	// is public context material (not secret). The raw Group DEK never crosses IPC.
	ActionGroupEncryptWithAAD = "group_encrypt_with_aad"

	// GroupTranscryptForGuest: re-encrypts an org Group-DEK token as an
	// external guest share without ever returning plaintext to the Extension
	// JS heap. Mirrors GroupDecryptToClipboard's input (group_handle + iv +
	// ciphertext) but the sink is a one-time guest key K re-encryption instead
	// of the clipboard.
	//
	// The Keeper unwraps the raw Group DEK behind the opaque handle, decrypts
	// the token inside a memguard-protected buffer, generates a fresh random
	// 32B guest key K, and AES-GCM-re-encrypts under a key derived from K
	// (optionally strengthened with a passphrase via HKDF(K ‖ PBKDF2(pass))).
	// The plaintext is zeroized the moment re-encryption completes.
	//   Inputs: group_handle, iv_b64(12B), ciphertext_b64,
	//           passphrase?(string), passphrase_salt?(base64, app-generated)
	//   Output: {guest_ciphertext (base64 IV‖ct), guest_key (base64url K)}
	// The output is byte-compatible with the admin SPA guest viewer
	// (app/src/shared/lib/guest-share-crypto.ts). Plaintext / Group DEK never
	// appear in the response.
	ActionGroupTranscryptForGuest = "group_transcrypt_for_guest"
)
