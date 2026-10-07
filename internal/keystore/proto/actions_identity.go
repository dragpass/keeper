// actions_identity.go — Wire-protocol Action* constants for account identity,
// device/session state, recovery, personal DEK, and request-signing keys.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	ActionAuthSignupPrepare          = "auth_signup_prepare"
	ActionAuthRecoveryReissuePrepare = "auth_recovery_reissue_prepare"
	ActionAuthRecoveryBegin          = "auth_recovery_begin"
	ActionAuthRecoveryPrepare        = "auth_recovery_prepare"
	// AuthRecoveryAbort drops the keypair a prepare staged, once the server
	// refused the recovery. It removes the staged pair only when its public
	// key is the one named, so the keyring returns to its pre-prepare bytes.
	ActionAuthRecoveryAbort = "auth_recovery_abort"
	// AuthSignupAbort drops the staged signup keypair, DEK and input record
	// once the server refused the signup, only when the staged public key is
	// the one named and the device has no active key.
	ActionAuthSignupAbort = "auth_signup_abort"
	// AuthLoginPending* sign in with an account key a signup or recovery
	// staged, for a device whose page was lost after the server accepted the
	// key and before save_session_code promoted it. The challenge is signed
	// only for the staged key the server-signed binding names, after the
	// password opens the server's password-wrapped DEK. Neither writes;
	// promotion stays in save_session_code.
	ActionAuthLoginPendingSignAlias     = "auth_login_pending_sign_alias"
	ActionAuthLoginPendingSignChallenge = "auth_login_pending_sign_challenge"

	// Device key related actions
	//
	// No action returns or accepts the raw 32B deviceKey. getdevicekey and
	// savedevicekey did, and were removed in 0.0.58 once every supported
	// extension used DeviceKeyStatus / DeviceKeyEnsure.
	ActionDeleteDeviceKey = "deletedevicekey"
	// DeviceKeyStatus reports whether a device key is stored ({ present }).
	// DeviceKeyEnsure generates a CSPRNG 32B key inside Keeper and stores it
	// in the device key Keychain slot, only when none exists
	// ({ created }). The check and the write run under the keychain process
	// lock. Neither returns or accepts key bytes.
	ActionDeviceKeyStatus = "device_key_status"
	ActionDeviceKeyEnsure = "device_key_ensure"

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
	// session_code, device_key, and the MLS leaf signature key, active and
	// pending (mls_leaf_signature_key, mls_leaf_signature_key_pending), plus
	// every owner's chat state (the sealed
	// files, the anchors, and the seal keys). server_public_key is an
	// account-independent trust anchor and is deliberately preserved.
	//
	// This is a purely local, destructive action. It returns no secret
	// material — only the names of the slots actually removed. It is
	// idempotent: success even when nothing was present. Worst case is that the
	// device must re-enroll; the account still exists server-side and remains
	// reachable via password / recovery key.
	ActionResetDeviceIdentity = "reset_device_identity"

	// Device identity and account binding (0.0.58), so the App and the
	// Extension share one server device and the Extension can sign itself in.
	// None of these reads or returns key material.
	//
	// DeviceIDEnsure returns this machine's device id, choosing it on the
	// first call: the stored id, else the device id of an existing MLS leaf
	// record (so the leaf never has to move), else the caller's candidate,
	// else a new UUID. It never changes a stored id; reset_device_identity is
	// the only way to clear it.
	//
	// AccountBindingSet records which account the App signed in to
	// ({ account_id, alias }) as a hint. DeviceAccountStatus reports the
	// device id, the binding, the active account key's fingerprint and
	// whether a device master is stored. DeviceSignout deletes the device
	// master only, marks the binding signed out and closes this process's
	// group session handles; the account key stays. AccountBindingSignout
	// marks only the binding signed out ("log out of all devices"): the
	// device master stays too.
	ActionDeviceIDEnsure        = "device_id_ensure"
	ActionAccountBindingSet     = "account_binding_set"
	ActionDeviceAccountStatus   = "device_account_status"
	ActionDeviceSignout         = "device_signout"
	ActionAccountBindingSignout = "account_binding_signout"

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
	//   Base64(iv||ct), or (0.0.58) none to rotate the one in the
	//   personal_device_wrapped_dek slot, and:
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
	ActionRecoverySign = "recoverysign"

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
	// Subsequent recoverysign / dek_rewrap_with_old_key_to_self actions take a
	// recovery_handle instead of old_private_key_pem and operate on the
	// PEM bytes from the store.
	ActionRecoverySessionOpen  = "recovery_session_open"
	ActionRecoverySessionClose = "recovery_session_close"

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

	// DEKUnwrapAndEncryptWithAAD: AAD-binding variant of
	// DEKUnwrapAndEncrypt, the personal-scope sibling of
	// GroupEncryptWithAAD.
	//   Inputs: encrypted_dek_b64, plaintext_b64, aad_b64 (required)
	//   Output: iv_b64, ciphertext_b64
	// Binds the caller-supplied canonical AAD (account_id|entry_id|
	// payload_kind|schema_version|dek_version) into the GCM tag so a sealed
	// personal credential payload cannot be opened under a different context.
	// aad_b64 is public context material, not secret.
	ActionDEKUnwrapAndEncryptWithAAD = "dek_unwrap_and_encrypt_with_aad"

	// DEKUnwrapAndDecryptToClipboard: decrypt-to-clipboard. After DEK
	// unwrap+decrypt, the Keeper writes the plaintext directly to the OS
	// clipboard. The response does not contain the plaintext — only
	// {copied, clipboard_ttl_ms}. Prevents the plaintext from living in the
	// Extension JS heap / Native Messaging response / React state
	// (security/keeper-plaintext-command-api-plan.md).
	ActionDEKUnwrapAndDecryptToClipboard = "dek_unwrap_and_decrypt_to_clipboard"

	// PersonalDEKAdopt (0.0.58): stores the Extension's old copy of the
	// device-wrapped personal DEK in personal_device_wrapped_dek, only when
	// the slot is empty, the device is not signed out and the copy opens
	// with the stored device key, all under the keychain process lock.
	//   Inputs: device_wrapped_dek_b64(iv(12)||ct)
	//   Output: adopted, reason? (signed_out | slot_occupied)
	// The only action that writes a caller-supplied wrap into the slot.
	// Native Messaging only: the App never held a copy.
	ActionPersonalDEKAdopt = "personal_dek_adopt"

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

	// MLS leaf signature key, two-phase like the account keypair rotation.
	//
	// MLSLeafDeclare mints this device's MLS leaf signature key — a
	// per-device Ed25519 key, never the account RSA key — for enroll or
	// rotate, and returns a declaration binding (account_id, device_id, key
	// fingerprint, validity window) under the account identity key. Key and
	// declaration go to the pending slot; the active slot does not change.
	// While a pending entry exists every declare call returns it and mints
	// nothing, so a retry after a lost response cannot fork the key. Gated by
	// a server-signed challenge like rotate_user_keypair_prepare, the other
	// action that signs a peer-visible statement with that key. The private
	// half never leaves the Keeper.
	//
	// MLSLeafPromote moves pending to active once ariadne's signed acceptance
	// names exactly the pending entry; a token naming the active entry is a
	// duplicate promote and succeeds without changing anything.
	// MLSLeafAbort discards the pending entry (idempotent). MLSLeafStatus
	// reports which entries exist, by fingerprint only.
	ActionMLSLeafDeclare = "mls_leaf_declare"
	ActionMLSLeafPromote = "mls_leaf_promote"
	ActionMLSLeafAbort   = "mls_leaf_abort"
	ActionMLSLeafStatus  = "mls_leaf_status"

	// MLSLeafHandoverSign is the old device's approval of a takeover (0.0.55,
	// design Q1): it checks that new_declaration is this account's, signed by
	// the account key this device holds, for another device, and signs a
	// handover statement with this device's active leaf key. The app calls it
	// only after a person on this device approved the request it shows. It
	// is not gated by a server challenge: it signs nothing the server could
	// not already relay, and without a declaration signed by this account's
	// key there is nothing to approve. It is not on the MCP surface.
	//
	//   Inputs: account_id, new_declaration, expires_at
	//   Output: handover
	ActionMLSLeafHandoverSign = "mls_leaf_handover_sign"

	// MLSKeyPackageGenerate produces single-use KeyPackages for this device's
	// active leaf, each carrying the active leaf declaration in a LeafNode
	// extension and ending no later than it, for the caller to upload to the
	// pool; their private keys go into the owner's sealed KeyPackage pool
	// before the response is built. There is no last-resort KeyPackage.
	// Gated by the purpose-bound dragpass.mls.keypackage.challenge, like
	// mls_leaf_declare and for the same reason: a tool call must not be able
	// to put this device into groups. Not a conversation-state permit, which a
	// device with no conversation yet cannot have.
	//
	//   Inputs: challenge_token, server_signature, server_key_version?,
	//           account_id, device_id, count (1..32)
	//   Output: { key_packages: [{ key_package_b64, not_after }] }
	MLSKeyPackageGenerate = "mls_key_package_generate"
)
