// actions.go — Wire-protocol Action* string constants.
//
// These constants are the `Action` field values in the Native Messaging
// request envelope and form part of the Extension(JS) ↔ Keeper(Go) wire
// protocol contract. The dispatcher's actionRegistry uses them as string
// keys to look up handlers.
//
// dispatcher.go and handler files under keystore root reference these via
// aliases (added in proto_aliases.go) by bare name (`ActionPing` etc.).

package proto

const (
	// Health check action
	ActionPing = "ping"

	// Device key related actions
	ActionGetDeviceKey    = "getdevicekey"
	ActionSaveDeviceKey   = "savedevicekey"
	ActionDeleteDeviceKey = "deletedevicekey"

	// Device identity reset — local self-recovery action.
	//
	// ResetDeviceIdentity wipes this device's account-scoped key material so
	// the user can re-enroll after a server-side account/DB reset. Without it,
	// leftover Keychain state (active keypair + session code) makes
	// HandleSignAlias refuse signup forever with "device already registered"
	// (identity_sign.go guard) and there is no Extension-callable escape.
	//
	// Clears: active keypair (keeper_private_key / keeper_public_key), pending
	// keypair (pending_keeper_private_key / pending_keeper_public_key),
	// session_code, and device_key. server_public_key is an account-independent
	// trust anchor and is deliberately preserved.
	//
	// This is a purely local, destructive action. It returns no secret
	// material — only the names of the slots actually removed. It is
	// idempotent: success even when nothing was present. Worst case is that the
	// device must re-enroll; the account still exists server-side and remains
	// reachable via password / recovery key.
	ActionResetDeviceIdentity = "reset_device_identity"

	// Session code related actions
	ActionGetSessionCode = "getsessioncode"

	// related to signup flow
	ActionSignAlias       = "signalias"
	ActionSaveSessionCode = "savesessioncode"

	// related to login flow
	ActionSignAliasWithTimestamp = "signaliaswithtimestamp"
	ActionSignChallengeToken     = "signchallengetoken"

	// related to login on another device
	ActionGenerateKeypair    = "generatekeypair"
	ActionGetPublicKey       = "getpublickey"
	ActionGetServerPublicKey = "getserverpubkey"

	// Server multi-version public-key infrastructure.
	//
	// RefreshServerKeys: Extension forwards the server's
	// `GET /api/v1/system/server-keys` response as-is. The Keeper (with
	// Root pubkey embedded) verifies the Root signature, then bulk-updates
	// the multi-version slots in the Keychain. Includes fingerprint TOFU
	// pinning. Intended to be called by the Extension on a chrome.alarms
	// 24h schedule.
	ActionRefreshServerKeys = "refresh_server_keys"

	// User RSA keypair voluntary rotation (2-step).
	//
	// RotateUserKeypairPrepare: generate a new keypair → save to pending
	//   slot, sign challenge with ACTIVE(OLD) priv + sign challenge with
	//   PENDING(NEW) priv.
	//   Response: {new_public_key, old_signature, new_signature}.
	//   ACTIVE is kept — the Extension uses the OLD priv while
	//   re-wrapping group_member_deks.
	//
	// RotateUserKeypairPromote: verify the server's
	//   confirmation_token signature, then call promotePendingKeypair() →
	//   pending → active, retire OLD.
	//   Response: {promoted, active_public_key}. On partial failure
	//   promote is not called → OLD stays.
	ActionRotateUserKeypairPrepare = "rotate_user_keypair_prepare"
	ActionRotateUserKeypairPromote = "rotate_user_keypair_promote"

	// Recovery for partial-failure of user RSA keypair rotation.
	//
	// RotateUserKeypairStatus: returns whether a pending slot exists +
	//   pending/active public keys. Called by the Extension before
	//   starting a rotation to detect a stuck state (pending lingers and
	//   the server's public_key matches the pending one).
	//   Response: {has_pending: bool, pending_public_key: string|"",
	//              active_public_key: string}
	//
	// RotateUserKeypairAbort: force-disposes the pending slot (idempotent).
	//   Called when the user picks "discard keypair" out of a stuck state.
	//   Does not touch the active keypair.
	//   Response: {aborted: bool}  // whether something was actually
	//   wiped (false if neither slot existed).
	ActionRotateUserKeypairStatus = "rotate_user_keypair_status"
	ActionRotateUserKeypairAbort  = "rotate_user_keypair_abort"

	// DeviceKey voluntary rotation (single composite action).
	//
	// RotateDeviceKey: takes the current device-wrapped personal DEK
	//   Base64(iv||ct) and:
	//   - fetches the current deviceKey from the Keychain (memguard)
	//   - unwraps the input wrap with the OLD deviceKey → raw 32B DEK
	//     (memguard)
	//   - generates a new 32B deviceKey (memguard)
	//   - wraps the raw DEK with the new deviceKey →
	//     new_device_wrapped_dek_b64
	//   - saves the new deviceKey to the Keychain (overwriting OLD)
	//   - zeroizes all plaintext and returns the new wrap
	//
	// The raw 32B personal DEK does not live in the Extension JS heap —
	// the Keeper composite action handles unwrap + wrap in one shot. The
	// server is unaffected (the server `accounts.encrypted_dek` is the
	// password wrap, which is independent).
	ActionRotateDeviceKey = "rotate_device_key"

	// related to recovery flow
	// RecoverySign: signs the challenge token with the temporarily-supplied
	//               old private-key PEM, then disposes of it immediately.
	//               Not stored in the Keychain.
	// GenerateKeypairWithRecoveryWrap: generates a new RSA keypair → wraps
	//                                  the private key with the supplied
	//                                  wrap_key via AES-GCM → returns the
	//                                  wrapped result + public key. Stores
	//                                  the new keypair in the Keychain as
	//                                  active.
	ActionRecoverySign                    = "recoverysign"
	ActionGenerateKeypairWithRecoveryWrap = "generatekeypairwithrecoverywrap"

	// Recovery key re-issue — admin SPA Settings · Security modal.
	// Issues a new RK24 only, while the user is already authenticated.
	// Re-wraps the existing active Keeper privkey with the new RK24 wrap_key
	// to produce a wrappedKeeper for server update.
	// The keypair itself does not change (this is the difference vs
	// RecoverySign / GenerateKeypair... ).
	ActionWrapActivePrivateKey = "wrap_active_private_key"

	// Master password change — admin SPA Settings · Security modal.
	// Returns the device-wrapped DEK re-wrapped with the new
	// password's PBKDF2 KEK. The deviceMaster itself does not change
	// (deviceKey is preserved). The DEK itself does not change either.
	ActionDEKRotateToNewPassword = "dek_rotate_to_new_password"

	// Recovery old PEM opaque handle.
	//
	// RecoverySessionOpen:  Extension sends a wrap_key derived from the
	//                       RK24 wrap path along with the server response's
	//                       wrappedKeeper; the Keeper verifies the
	//                       challenge → AES-GCM unwraps to restore the raw
	//                       PEM → keeps it in memguard → issues a handle.
	//                       The PEM never lives in the IPC payload or the
	//                       Extension JS heap.
	// RecoverySessionClose: explicit handle disposal (the Extension calls
	//                       it when Recovery completes).
	//
	// Subsequent recoverysign / dek_rewrap_with_old_key actions take a
	// recovery_handle instead of old_private_key_pem and operate on the
	// PEM bytes from the store.
	ActionRecoverySessionOpen  = "recovery_session_open"
	ActionRecoverySessionClose = "recovery_session_close"

	// related to team encryption
	// WrapGroupDEK:   takes the recipient's RSA public key PEM and returns
	//                 the Group DEK (raw 32B) RSA-OAEP-SHA256-wrapped as
	//                 Base64. No Keychain access (public key only). Shared
	//                 by 3 paths: team creation / member invite / Recovery
	//                 re-wrap.
	// UnwrapGroupDEK: RSA-OAEP-decrypts encrypted_group_dek(Base64) with
	//                 my active private key in the Keychain and returns
	//                 the raw 32B as Base64. The plaintext is briefly
	//                 protected by memguard and zeroized right after
	//                 returning.
	ActionWrapGroupDEK   = "wrapgroupdek"
	ActionUnwrapGroupDEK = "unwrapgroupdek"

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
	// GroupSessionOpen:        takes wrapped_group_dek and (with the
	//                          active Keychain priv key) RSA-OAEP-unwraps
	//                          to keep the raw 32B in Keeper memguard.
	//                          Returns a 32B random handle ID (Base64) and
	//                          expires_at_ms (Unix ms). The Extension
	//                          never sees the raw bytes on the normal path.
	// GroupSessionOpenWithRaw: takes a raw 32B Group DEK Base64 directly
	//                          and registers it in the store.
	//                          **DEK rotation only — escape hatch**: at
	//                          rotation a new DEK is generated on the
	//                          Extension side (generateRawGroupDEK) or the
	//                          old DEK is fetched from the server in
	//                          plaintext. Handle registration is needed
	//                          only in this brief window, so a raw input
	//                          is allowed. Normal operations
	//                          (drag / draglink / share) use
	//                          GroupSessionOpen only.
	// GroupSessionClose:       destroys and removes the handle. Idempotent
	//                          (missing handles are OK).
	// GroupSessionStatus:      whether the handle exists + remaining TTL
	//                          in ms. Debugging / observability.
	//
	// Subsequent aes_* actions (4 of them) take group_handle instead of
	// group_dek_b64 and run AES-GCM against the same key material. The
	// raw Group DEK Base64 does not live in the Extension JS heap (except
	// during rotation).
	ActionGroupSessionOpen        = "group_session_open"
	ActionGroupSessionOpenWithRaw = "group_session_open_with_raw"
	ActionGroupSessionClose       = "group_session_close"
	ActionGroupSessionStatus      = "group_session_status"

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
	ActionGroupDEKGenerateAndOpen = "group_dek_generate_and_open"
	ActionDEKRewrapForMember      = "dek_rewrap_for_member"

	// Zero-Extractable: Item DEK operations delegated to the Keeper.
	//
	// All actions take group_handle + a wrapped Item DEK and temporarily
	// unwrap the Item DEK inside the Keeper to run AES-GCM. The raw Group
	// DEK lives behind the GroupSessionStore opaque handle; on the normal
	// operational path the raw Group DEK Base64 does not live in the
	// Extension JS heap.
	//
	// AESGenerateAndWrap:    generate a rand 32B Item DEK → AES-GCM-wrap
	//                        with the Group DEK → return
	//                        {item_dek_raw_b64, wrapped_item_dek}.
	//                        Replaces generateItemDEK + wrapItemDEK.
	// AESUnwrapAndEncrypt:   unwrap the wrapped Item DEK with the Group DEK
	//                        and AES-GCM-encrypt plaintext → return
	//                        {iv_b64, ciphertext_b64}. Braille encoding is
	//                        the Extension's job.
	// (The old AESUnwrapAndDecrypt — plaintext-returning action — was
	//  removed. Replaced by AESUnwrapAndDecryptToClipboard /
	//  AESUnwrapAndDecryptMeta.)
	// (AESRewrap — cross-group Item DEK rewrap — was removed alongside
	//  the item_dek_grants schema.)
	ActionAESGenerateAndWrap  = "aes_generate_and_wrap"
	ActionAESUnwrapAndEncrypt = "aes_unwrap_and_encrypt"
	// AESUnshareRewrapMeta: UNSHARE_REENCRYPT composite.
	ActionAESUnshareRewrapMeta = "aes_unshare_rewrap_meta"
	// AESUnwrapAndDecryptMeta: bulk-decrypt group entry metadata fields.
	// Carve-out for plaintext metadata in response — value (secret) is
	// split off.
	ActionAESUnwrapAndDecryptMeta = "aes_unwrap_and_decrypt_meta"

	// DEKGenerateAndWrapPassword: moves the signup flow's generateDEK +
	// wrapDEKWithPassword into the Keeper. PBKDF2(password) → KEK →
	// AES-GCM(DEK) → returns {encrypted_dek_b64}. Braille encoding stays
	// in the Extension.
	ActionDEKGenerateAndWrapPassword = "dek_generate_and_wrap_password"

	// DEKGenerateAndWrapDual: dual wrap for the signup flow. Generates a
	// new 32B DEK and AES-GCM-wraps it with both (1) the password-derived
	// KEK and (2) the deviceKey raw bytes, returning both wraps in one
	// shot. The Extension never sees plaintext DEK.
	//   For server:  Base64(salt(16) || iv(12) || ciphertext) — the
	//                Extension Braille-encodes it.
	//   For local:   Base64(iv(12) || ciphertext)             — the
	//                Extension Braille-encodes it.
	// Replaces 3 calls (generateDEK + wrapDEKWithPassword +
	// wrapDEKWithDeviceKey) with a single Keeper round-trip.
	ActionDEKGenerateAndWrapDual = "dek_generate_and_wrap_dual"

	// DEKRotateToDeviceKey: login flow. Unwraps the password-wrapped DEK
	// received from the server using the password and re-wraps it with
	// the deviceKey. The plaintext DEK only briefly exists inside Keeper
	// memguard.
	//   Inputs: password + encrypted_dek_b64(salt(16)||iv(12)||ct)
	//   The deviceKey is not in the IPC payload — the Keeper fetches it
	//   directly from the Keychain.
	//   Output: device_wrapped_dek_b64(iv(12)||ciphertext)
	// Replaces useLogin's rotateDEKSafely step with a single Keeper
	// round-trip.
	ActionDEKRotateToDeviceKey = "dek_rotate_to_device_key"

	// DEKUnwrapAndEncrypt: unwraps the device-wrapped personal DEK and
	// AES-GCM-encrypts plaintext with it.
	//   Inputs: encrypted_dek_b64(iv(12)||ct), plaintext_b64
	//   The deviceKey is not in the IPC payload — the Keeper fetches it
	//   directly from the Keychain.
	//   Output: iv_b64, ciphertext_b64 (the Extension assembles the token
	//   via buildTokenFromCiphertext).
	// Moves dekManager.encryptData into the Keeper.
	ActionDEKUnwrapAndEncrypt = "dek_unwrap_and_encrypt"

	// (The old DEKUnwrapAndDecrypt — plaintext-returning action — was
	//  removed. Replaced by DEKUnwrapAndDecryptToClipboard /
	//  DEKUnwrapAndDecryptMeta.)

	// DEKUnwrapAndDecryptMeta: bulk-decrypt personal entry metadata fields.
	//   Inputs: encrypted_dek_b64, meta_fields (key→Base64(IV(12)||ct))
	//   Output: fields (key→plaintext UTF-8)
	// Carve-out for plaintext metadata in response — value is split off
	// (consumed via decrypt-to-clipboard).
	ActionDEKUnwrapAndDecryptMeta = "dek_unwrap_and_decrypt_meta"

	// AESUnwrapAndDecryptToClipboard / DEKUnwrapAndDecryptToClipboard:
	// decrypt-to-clipboard. After AES/DEK unwrap+decrypt, the Keeper
	// writes the plaintext directly to the OS clipboard. The response
	// does not contain the plaintext — only {copied, clipboard_ttl_ms}.
	// Prevents the plaintext from living in the Extension JS heap /
	// Native Messaging response / React state
	// (security/keeper-plaintext-command-api-plan.md).
	ActionAESUnwrapAndDecryptToClipboard = "aes_unwrap_and_decrypt_to_clipboard"
	ActionDEKUnwrapAndDecryptToClipboard = "dek_unwrap_and_decrypt_to_clipboard"

	// GroupDecryptToClipboard: action where the Keeper unwraps a drag /
	// audit token (raw Group DEK direct encryption) and writes the
	// plaintext directly to the OS clipboard. For raw Group DEK tokens
	// only — not DragLink Item DEK tokens (which use Item DEK indirection).
	//   Inputs: group_handle, iv_b64(12B), ciphertext_b64,
	//           clipboard_ttl_ms
	//   Output: {copied, clipboard_ttl_ms}
	ActionGroupDecryptToClipboard = "group_decrypt_to_clipboard"

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

	// per-device request-signing key actions.
	//
	// RequestKeyGenerate: generate an Ed25519 keypair. If an active key
	//                     already exists, this is a no-op (status only).
	//                     force_rotate is handled by a separate P4
	//                     rotation action.
	// RequestKeyStatus:   whether an active key exists + public key +
	//                     fingerprint.
	// SignRequest:        signs a canonical request string with the
	//                     active key. canonical_request is metadata only
	//                     — never includes plaintext / token / secret
	//                     itself (security requirement).
	ActionRequestKeyGenerate = "request_key_generate"
	ActionRequestKeyStatus   = "request_key_status"
	ActionSignRequest        = "sign_request"

	// request-signing key rotation (3-step: prepare / promote / abort).
	//
	// RotateRequestKeyPrepare: new ed25519 keypair → save to pending slot,
	//   sign challenge with ACTIVE(OLD) priv + sign challenge with
	//   PENDING(NEW) priv.
	//   Response: {new_public_key, old_signature, new_signature}.
	//   ACTIVE stays — until the server moves it to retiring, the ACTIVE
	//   slot is still used for sign_request.
	// RotateRequestKeyPromote: pending → active, retire OLD. Called by
	//   the Extension after the server confirms rotation success with
	//   200 OK.
	// RotateRequestKeyAbort: dispose of the pending slot (idempotent).
	//   Cleanup after failure.
	ActionRotateRequestKeyPrepare = "rotate_request_key_prepare"
	ActionRotateRequestKeyPromote = "rotate_request_key_promote"
	ActionRotateRequestKeyAbort   = "rotate_request_key_abort"

	// per-org Archive / Recovery keypair actions.
	//
	// ArchiveKeyGenerate: generate an RSA archive keypair. If an active key
	//                     already exists, this is a no-op returning only its
	//                     meta (idempotent). The private key is stored in a
	//                     dedicated slot and never leaves it.
	// ArchiveKeyStatus:   whether an active archive key exists + public key +
	//                     fingerprint. Absence is normal (archive not enabled).
	//
	// The archive key is a break-glass recovery key: during group DEK rotation
	// the OLD Group DEK is additionally wrapped to its public half so the org
	// owner can recover past DEKs. It is never used for identity / login /
	// recovery / request signing.
	ActionArchiveKeyGenerate = "archive_key_generate"
	ActionArchiveKeyStatus   = "archive_key_status"

	// ArchiveUnwrapAndRewrap: break-glass re-grant composite. Unwrap an OLD
	// Group DEK that was wrapped to the org archive public key
	// (org_owner_archive grant) with the archive private key, then re-wrap it
	// to a target member's public key. The raw Group DEK lives only briefly in
	// Keeper memory (memguard) and is never in the response — same raw-free
	// pattern as dek_rewrap_for_member. The archive private key never leaves
	// its slot. Missing archive slot → not_found.
	ActionArchiveUnwrapAndRewrap = "archive_unwrap_and_rewrap"

	// ClipboardGetLastHash: test-only — used by the Extension `pnpm e2e`
	// flow to verify that the dispatch path
	// (background → Keeper → Clipboard.Write) sent the correct plaintext.
	// Returns the SHA-256 hash recorded by MemoryClipboard + the write
	// count. In production OSClipboard this is rejected with
	// ErrCodeUnsupported — the action only returns a meaningful answer
	// in KEEPER_E2E_MODE.
	ActionClipboardGetLastHash = "clipboard_get_last_hash"
)
