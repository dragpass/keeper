// actions_identity.go — Wire-protocol Action* constants for account identity,
// device/session state, recovery, personal DEK, and request-signing keys.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	ActionAuthSignupPrepare          = "auth_signup_prepare"
	ActionAuthRecoveryKeyShow        = "auth_recovery_key_show"
	ActionAuthRecoveryReissuePrepare = "auth_recovery_reissue_prepare"
	ActionAuthRecoveryBegin          = "auth_recovery_begin"
	ActionAuthRecoveryPrepare        = "auth_recovery_prepare"

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
	ActionGenerateKeypair = "generatekeypair"
	ActionGetPublicKey    = "getpublickey"

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

	// DEKUnwrapAndDecryptToClipboard: decrypt-to-clipboard. After DEK
	// unwrap+decrypt, the Keeper writes the plaintext directly to the OS
	// clipboard. The response does not contain the plaintext — only
	// {copied, clipboard_ttl_ms}. Prevents the plaintext from living in the
	// Extension JS heap / Native Messaging response / React state
	// (security/keeper-plaintext-command-api-plan.md).
	ActionDEKUnwrapAndDecryptToClipboard = "dek_unwrap_and_decrypt_to_clipboard"

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
)
