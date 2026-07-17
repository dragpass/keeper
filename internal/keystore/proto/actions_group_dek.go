// actions_group_dek.go — Wire-protocol Action* constants for Group DEK and
// Item DEK operations: RSA wrap/unwrap, group session opaque handles, AES-GCM
// item ops, decrypt-to-clipboard, and guest transcrypt.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	// related to team encryption
	// WrapGroupDEK:   takes the recipient's RSA public key PEM and returns
	//                 the Group DEK (raw 32B) RSA-OAEP-SHA256-wrapped as
	//                 Base64. No Keychain access (public key only). Shared
	//                 by 3 paths: team creation / member invite / Recovery
	//                 re-wrap.
	//
	// (UnwrapGroupDEK — which RSA-OAEP-decrypted a wrapped Group DEK and
	//  returned the raw 32B over IPC — was removed. The raw Group DEK no
	//  longer crosses IPC in the unwrap direction; use group_session_open,
	//  which unwraps into a Keeper-held opaque handle instead.)
	ActionWrapGroupDEK = "wrapgroupdek"

	// DEKRewrapWithOldKey: composite Recovery re-wrap action. Handles the
	// old unwrapgroupdekwithkey + WrapGroupDEK pair inside the Keeper in one
	// shot. The raw Group DEK exists only inside a memguard LockedBuffer
	// and is zeroized right before the response →
	// **the raw never lives in the Extension JS heap.**
	//   Inputs: challenge_token + signature (verifies Recovery origin)
	//           + recovery_handle + encrypted_group_dek + new_public_key
	//   Output: new_encrypted_group_dek (new RSA-OAEP wrap result)
	// Reduces the Recovery group loop from 3 Keeper round-trips
	// (unwrap+wrap+put) to 1 (rewrap+put).
	ActionDEKRewrapWithOldKey = "dek_rewrap_with_old_key"

	// Group DEK opaque handle.
	//
	// GroupSessionOpen:   takes wrapped_group_dek and (with the active
	//                     Keychain priv key) RSA-OAEP-unwraps to keep the
	//                     raw 32B in Keeper memguard. Returns a 32B random
	//                     handle ID (Base64) and expires_at_ms (Unix ms).
	//                     The Extension never sees the raw bytes.
	// GroupSessionClose:  destroys and removes the handle. Idempotent
	//                     (missing handles are OK).
	// GroupSessionStatus: whether the handle exists + remaining TTL in ms.
	//                     Debugging / observability.
	//
	// Subsequent aes_* actions (4 of them) take group_handle instead of
	// group_dek_b64 and run AES-GCM against the same key material. The raw
	// Group DEK Base64 does not live in the Extension JS heap.
	//
	// (GroupSessionOpenWithRaw — which registered a raw 32B Group DEK Base64
	//  directly, a DEK-rotation escape hatch — was removed. No raw Group DEK
	//  crosses IPC in either direction; all group sessions open from a
	//  wrapped DEK via GroupSessionOpen.)
	ActionGroupSessionOpen   = "group_session_open"
	ActionGroupSessionClose  = "group_session_close"
	ActionGroupSessionStatus = "group_session_status"

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

	// Zero-Extractable: Item DEK operations delegated to the Keeper.
	//
	// All actions take group_handle + a wrapped Item DEK and temporarily
	// unwrap the Item DEK inside the Keeper to run AES-GCM. The raw Group
	// DEK lives behind the GroupSessionStore opaque handle; on the normal
	// operational path the raw Group DEK Base64 does not live in the
	// Extension JS heap.
	//
	// AESUnwrapAndEncrypt:   unwrap the wrapped Item DEK with the Group DEK
	//                        and AES-GCM-encrypt plaintext → return
	//                        {iv_b64, ciphertext_b64}. Braille encoding is
	//                        the Extension's job.
	// (The old AESUnwrapAndDecrypt — plaintext-returning action — was
	//  removed. Replaced by AESUnwrapAndDecryptToClipboard /
	//  AESUnwrapAndDecryptMeta.)
	// (AESRewrap — cross-group Item DEK rewrap — was removed alongside
	//  the item_dek_grants schema.)
	// (AESGenerateAndWrap — which returned a raw Item DEK over IPC — was
	//  removed as a vault-deprecation leftover; no raw Item DEK crosses IPC.)
	ActionAESUnwrapAndEncrypt = "aes_unwrap_and_encrypt"
	// AESUnshareRewrapMeta: UNSHARE_REENCRYPT composite.
	ActionAESUnshareRewrapMeta = "aes_unshare_rewrap_meta"
	// AESUnwrapAndDecryptMeta: bulk-decrypt group entry metadata fields.
	// Carve-out for plaintext metadata in response — value (secret) is
	// split off.
	ActionAESUnwrapAndDecryptMeta = "aes_unwrap_and_decrypt_meta"

	// AESUnwrapAndDecryptToClipboard: decrypt-to-clipboard. After AES
	// unwrap+decrypt, the Keeper writes the plaintext directly to the OS
	// clipboard. The response does not contain the plaintext — only
	// {copied, clipboard_ttl_ms}. Prevents the plaintext from living in the
	// Extension JS heap / Native Messaging response / React state
	// (security/keeper-plaintext-command-api-plan.md).
	ActionAESUnwrapAndDecryptToClipboard = "aes_unwrap_and_decrypt_to_clipboard"

	// GroupDecryptToClipboard: action where the Keeper unwraps a drag /
	// audit token (raw Group DEK direct encryption) and writes the
	// plaintext directly to the OS clipboard. For raw Group DEK tokens
	// only — not DragLink Item DEK tokens (which use Item DEK indirection).
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

	// GroupEncryptMeta / GroupDecryptMeta: raw Group DEK direct batch metadata
	// crypto. Same shape as aes_unwrap_and_decrypt_meta but with the Item DEK
	// unwrap step replaced by a direct raw Group DEK use behind the opaque
	// handle (mirror of group_encrypt vs aes_unwrap_and_encrypt).
	//
	// GroupDecryptMeta: group_handle + meta_fields (key→Base64(IV(12)||ct)) →
	//                   {fields} (key→plaintext UTF-8). Batch decrypt for the
	//                   DragLink page. Plaintext metadata carve-out — value
	//                   plaintext is never returned here.
	// GroupEncryptMeta: group_handle + fields (key→plaintext UTF-8) →
	//                   {meta_fields} (key→Base64(IV(12)||ct)). The inverse of
	//                   GroupDecryptMeta: its meta_fields output is directly
	//                   feedable back as GroupDecryptMeta's meta_fields input,
	//                   and the combined Base64(IV||ct) form matches what the
	//                   Extension stores per meta field. plaintext / raw Group
	//                   DEK echoed 0 times.
	ActionGroupEncryptMeta = "group_encrypt_meta"
	ActionGroupDecryptMeta = "group_decrypt_meta"

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
