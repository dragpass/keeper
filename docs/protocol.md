# DragPass Keeper — Native Messaging Protocol

> Public protocol contract between the DragPass Chrome Extension and the
> dragpass-keeper Native Messaging app. Treat this document as the authoritative
> source of truth — when adding or changing actions, update this file in the
> same PR.
>
> Field names below are the actual JSON tags emitted/parsed by Keeper (see
> `internal/keystore/proto/`). They are reproduced here verbatim — do not
> paraphrase. Any drift between this file and the `proto` package is a bug.

## Transport

- Channel: Chrome Native Messaging (stdin/stdout pipe, length-prefixed JSON).
- Encoding: UTF-8 JSON. No nested binary framing.
- Direction: Extension → Keeper (request), Keeper → Extension (response).
- Concurrency: Multiple in-flight requests are dispatched by `request_id`.
  Older Extension builds without `request_id` fall back to FIFO matching.

## Envelope

### Request

```json
{
  "action": "<action_name>",
  "request_id": "<opaque-string-uuid>",
  "payload": { ... }
}
```

|Field|Type|Required|Notes|
|---|---|---|---|
|`action`|string|yes|One of the action names listed below.|
|`request_id`|string|no\*|Opaque correlation ID. \*Older Extension may omit; Keeper echoes empty.|
|`payload`|object|varies|Action-specific request body. May be omitted for actions with no inputs.|

### Response

```json
{
  "success": true,
  "request_id": "<echoed-from-request>",
  "data": { ... }
}
```

```json
{
  "success": false,
  "request_id": "<echoed-from-request>",
  "error": "<short reason, no secrets>",
  "error_code": "<coarse category — see Error codes>"
}
```

|Field|Type|Required|Notes|
|---|---|---|---|
|`success`|boolean|yes|`true` for success, `false` for any error.|
|`request_id`|string|no|Echo of request `request_id`. Empty when request omitted it.|
|`data`|object|varies|Present on success. Action-specific response body.|
|`error`|string|varies|Present on failure. Short, deterministic reason. **Must not include secret values.**|
|`error_code`|string|varies|Present on failure. Coarse category for Extension-side branching (see Error codes). `omitempty` — older Keeper builds may omit.|

### `server_key_version` (optional, many requests)

Several actions accept an optional `server_key_version` field on the request
payload (see Phase 13b multi-version server keys). Semantics:

- `0` (or omitted) — Keeper falls back to the active server public key version
  pinned in the Keychain.
- `>= 1` — Keeper uses the pinned PEM for that specific version. If the version
  is unknown to Keeper, the action fails with `error_code = "not_found"`. The
  Extension is expected to refresh server keys (see `refresh_server_keys`) and
  retry once.

Actions that accept it: `generatekeypair`, `savesessioncode`, `signchallengetoken`,
`recoverysign`, `generatekeypairwithrecoverywrap`, `recovery_session_open`,
`dek_rewrap_with_old_key`, `rotate_user_keypair_prepare`, `rotate_user_keypair_promote`.

## Sensitive payload classification

Fields are classified according to their leakage cost. Treat the classification
as a contract:

|Class|Examples|Logging|
|---|---|---|
|`secret`|`password`, `passphrase`, raw DEK Base64 (`group_dek_b64`, `item_dek_raw_b64`), `plaintext_b64`, `wrap_key_b64`|Never log|
|`wrapped`|`wrapped_item_dek`, `encrypted_dek_b64`, `wrapped_keeper`, `wrapped_keeper_b64`, `encrypted_group_dek`, `wrapped_for_me_b64`, `wrapped_for_archive_b64`, `encrypted_for_other_b64`, `device_wrapped_dek_b64`, `password_wrapped_dek_b64`|Never log|
|`handle`|`group_handle`, `recovery_handle`, `src_group_handle`, `dst_group_handle` (32B random ID)|OK to log|
|`metadata`|`server_key_version`, `request_id`, `expires_at_ms`, `remaining_ms`, `version`|OK to log|
|`public material`|`publickey`, `recipient_public_key`, `my_public_key`, `other_public_key`, `new_public_key`, `iv_b64`, `ciphertext_b64` (already enc), `challenge_token`, `signature` (Base64 over public token)|OK to log|

Validation errors echo **field names only**, never the field's value
(see `internal/keystore/proto/validation.go`).

## Action catalog

Action names are the literal strings used in the `action` envelope field.
Implementation lives in `internal/keystore/handlers/`. The corresponding Go
types are in `internal/keystore/proto/`.

### Health

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`ping`|_empty_|`{ version, hash, path }`|Liveness + version. Used by Extension health check.|

### Device key (per-device wrap layer)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`getdevicekey`|_empty_|`{ key }`|Fetch deviceKey from OS Keychain. `key` = Base64(raw 32B).|
|`savedevicekey`|`key`|_empty_|Save deviceKey. `key` = Base64(raw 32B). Used during signup.|
|`deletedevicekey`|_empty_|_empty_|Remove deviceKey from Keychain (account reset).|
|`reset_device_identity`|_empty_|`{ cleared }`|Local self-recovery: wipe this device's account-scoped key material — active keypair (`keeper_private_key`/`keeper_public_key`), pending keypair (`pending_keeper_private_key`/`pending_keeper_public_key`), `session_code`, `device_key` — so the user can re-enroll after a server-side account/DB reset. `cleared` = names of slots actually removed (idempotent: `[]` when nothing was present). `server_public_key` is preserved (account-independent trust anchor). Returns no key material.|
|`rotate_device_key`|`device_wrapped_dek_b64`|`{ device_wrapped_dek_b64 }`|One-shot rotation. Request carries the **current** wrap; response carries the **new** wrap. raw 32B DEK never leaves Keeper memory.|

### Session code

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`getsessioncode`|_empty_|`{ session_code }`|Fetch session code (for re-auth).|
|`savesessioncode`|`encrypted_session_code`, `signature`, `server_key_version?`|`{ session_code }`|Verify server signature on `encrypted_session_code`, decrypt with active privkey, persist, and echo plaintext `session_code`.|

### Identity / signup / login

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`signalias`|`alias`, `wrap_key_b64?`|`{ signature, publickey, wrapped_keeper? }`|Signup challenge signing. If `wrap_key_b64` is non-empty, Keeper also returns the freshly generated pending privkey AES-GCM-wrapped under that key (Phase 2 Recovery setup).|
|`signaliaswithtimestamp`|`alias`|`{ signature, timestamp }`|Login challenge signing. Keeper produces `timestamp` (Unix seconds) and signs `alias‖timestamp`.|
|`signchallengetoken`|`challenge_token`, `signature`, `server_key_version?`|`{ signature }`|Re-auth challenge. Verifies server signature on `challenge_token`, then signs with active privkey.|
|`generatekeypair`|`challenge_token`, `signature`, `server_key_version?`|`{ publickey }`|Generate RSA keypair on this device. Verifies server signature first.|
|`getpublickey`|_empty_|`{ publickey }`|Read active public key from Keychain.|
|`getserverpubkey`|_empty_|`{ publickey }`|Read pinned active server public key PEM.|

### Per-device request signing (Phase 18)

An Ed25519 keypair in a separate namespace. Never mix with the identity
keypair (RSA, signalias/login/recovery paths). This key is not used for
Group DEK unwrap / login challenge / recovery — it is dedicated to signing
general API requests.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`request_key_generate`|`force_rotate?` (ignored until P4)|`{ publickey, fingerprint }`|Generate a new Ed25519 keypair if no active key exists. If one already exists, idempotently return only the metadata.|
|`request_key_status`|_empty_|`{ has_active, publickey?, fingerprint? }`|Whether an active key exists + the public key. Before enroll, has_active=false.|
|`sign_request`|`canonical_request`|`{ signature, publickey, fingerprint }`|Sign the canonical request string (metadata only, no plaintext payload) with the active key.|
|`rotate_request_key_prepare`|`challenge_token`|`{ new_public_key, old_signature, new_signature, old_key_id }`|Generate a new Ed25519 keypair → store in the pending slot, sign challenge with both OLD and NEW priv. ACTIVE untouched.|
|`rotate_request_key_promote`|_empty_|`{ promoted, active_public_key, fingerprint }`|Promote pending → active, discard OLD. Called immediately after the server rotation complete 200 response.|
|`rotate_request_key_abort`|_empty_|`{ aborted }`|Force-discard the pending slot. Idempotent (aborted=false if neither exists).|

`canonical_request` is the LF-separated 10-field string from the dp-req-v1
spec. It must
never contain plaintext payload / tokens / secrets themselves — the handler
does not inspect the input, so this is the caller's responsibility.

### Per-org Archive / Recovery keypair

A break-glass recovery keypair (RSA-2048) held on the org owner's device in a
dedicated Keychain slot (`org_archive_private_key` / `org_archive_public_key`),
completely separate from the account identity keypair and the request-signing
key. It is used only to additionally wrap OLD Group DEKs during rotation (an
`org_owner_archive` grant, defense-in-depth) — never for identity / login /
recovery / request signing. The private key never leaves its slot.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`archive_key_generate`|_empty_|`{ publickey, fingerprint }`|Generate an RSA archive keypair if no active key exists. If one already exists, idempotently return only its metadata. `publickey` is a PEM string; `fingerprint` is `hex(sha256(publickey PEM))`.|
|`archive_key_status`|_empty_|`{ has_active, publickey?, fingerprint? }`|Whether an active archive key exists + the public key. Before enable, has_active=false.|
|`archive_unwrap_and_rewrap`|`wrapped_for_archive_b64`, `recipient_public_key`|`{ encrypted_for_other_b64 }`|Break-glass re-grant composite. Unwrap an OLD Group DEK wrapped to the archive public key (`org_owner_archive` grant) with the archive private key → RSA-OAEP re-wrap to a target member's public key. raw Group DEK lives only in Keeper memory (memguard); the response carries only the new wrap. Missing archive slot → `not_found`. Same raw-free pattern as `dek_rewrap_for_member`.|

#### Archive-key admin quorum (Shamir N-of-M break-glass)

An alternative custody where the archive private key is Shamir-split across M
admin devices instead of held whole on the owner's device. After split the
whole private key exists nowhere at rest, only as shares. Break-glass then
requires N of M admins to approve within a coordinator-run recovery session.

A Shamir share of the archive private-key PEM (~1.7 KB) exceeds the RSA-OAEP
plaintext limit, so every wrapped share is a **hybrid envelope**: `wrapped_key`
is `Base64( RSA-OAEP( 32-byte AES key ) )` and `ciphertext` is
`Base64( IV(12) || AES-256-GCM(share) )`. The share's Shamir x-coordinate is
embedded (authenticated) inside the ciphertext, so a reconstruction cannot be
fed a wrong index. Shamir is an in-repo GF(2^8) implementation (no external
dependency).

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`archive_key_split`|`threshold_n`, `recipient_public_keys[]` (M admin account archive PEMs)|`{ shares: [{ share_index, wrapped_key, ciphertext, recipient_fingerprint }] }`|Shamir-split the archive private key into M shares (threshold N), hybrid-wrap share _i_ to `recipient_public_keys[i]`, then **delete** the archive private key (kept: the public key). Not idempotent — a missing private key → `not_found`.|
|`archive_share_rewrap`|`wrapped_key`, `ciphertext`, `session_public_key`|`{ wrapped_key, ciphertext }`|An approving admin re-wraps their own share from their account archive key (their archive slot) to the recovery session public key. Distinct from `archive_unwrap_and_rewrap` because shares are hybrid envelopes, not 32-byte DEKs. Missing admin archive slot → `not_found`.|
|`archive_session_begin`|_empty_|`{ session_public_key, fingerprint }`|Coordinator generates an ephemeral recovery-session keypair in its own slot (`org_archive_session_private_key`) and returns the public key. Supersedes any prior session key.|
|`archive_session_end`|_empty_|`{ ended }`|Destroy the recovery-session keypair. Idempotent (`ended=false` when none was open).|
|`archive_quorum_combine_and_rewrap`|`rewrapped_shares[]` (each `{ wrapped_key, ciphertext }` to the session key), `wrapped_old_dek_b64`, `recipient_public_keys[]`|`{ grants: [{ recipient_fingerprint, encrypted_group_dek_b64 }] }`|Coordinator unwraps the re-wrapped shares with the session private key, Shamir-reconstructs the archive private key, RSA-OAEP-unwraps the OLD Group DEK, and re-wraps it to each target member. All reconstructed key material (shares, private key, raw DEK) lives only in memguard and is wiped before returning. Below-threshold or tampered shares reconstruct a non-parsable key → `crypto_failure` (no silent wrong-DEK leak). Missing session slot → `not_found`.|

### Server key distribution (Phase 13b)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`refresh_server_keys`|`keys`, `root_public_key_fingerprint?`|`{ updated_versions, active_version, root_verified, rejected }`|Verify server `GET /api/v1/system/server-keys` response under embedded Root and update Keychain multi-version slots. `keys` is an array of `{ version, public_key_pem, issued_at, expires_at, status, root_signature? }`. `rejected` is reserved (currently always `[]`).|

### User keypair rotation (Phase 13e + 14a)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`rotate_user_keypair_prepare`|`challenge_token`, `server_signature`, `server_key_version?`|`{ new_public_key, old_signature, new_signature }`|Generate pending keypair, sign challenge with both OLD and NEW privkeys. ACTIVE remains OLD until promote.|
|`rotate_user_keypair_promote`|`confirmation_token`, `confirmation_payload`, `confirmation_signature`, `server_key_version?`|`{ promoted, active_public_key }`|Verify signed confirmation payload, check pending public key hash/expiry, promote pending → active.|
|`rotate_user_keypair_status`|_empty_|`{ has_pending, pending_public_key, active_public_key }`|Diagnose stuck state (Phase 14a).|
|`rotate_user_keypair_abort`|_empty_|`{ aborted }`|Discard pending slot (Phase 14a). `aborted=false` when neither slot existed (idempotent).|

### Recovery (Phase 2)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`recoverysign`|`challenge_token`, `signature`, `recovery_handle`, `server_key_version?`|`{ signature }`|Sign challenge with recovered OLD private key (PEM held in Keeper memguard via handle). `signature` (request) = server signature over `challenge_token`. `signature` (response) = OLD privkey signature over `challenge_token`.|
|`generatekeypairwithrecoverywrap`|`challenge_token`, `signature`, `wrap_key_b64`, `server_key_version?`|`{ publickey, wrapped_keeper }`|New keypair + AES-GCM-wrap private key with RK24-derived `wrap_key`. `wrapped_keeper` = Base64(IV‖ciphertext).|
|`recovery_session_open`|`challenge_token`, `signature`, `wrapped_keeper_b64`, `wrap_key_b64`, `server_key_version?`|`{ recovery_handle, expires_at_ms }`|Verify challenge, decrypt PEM into memguard, return opaque handle. PEM never crosses IPC.|
|`recovery_session_close`|`recovery_handle`|_empty_|Discard handle. Idempotent (no error if handle absent).|

### Group DEK

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`wrapgroupdek`|`group_dek_b64`, `recipient_public_key`|`{ encrypted_group_dek }`|RSA-OAEP-SHA256 wrap. `group_dek_b64` = Base64(raw 32B). `recipient_public_key` = PEM.|
|`unwrapgroupdek`|`encrypted_group_dek`|`{ group_dek_b64 }`|RSA-OAEP unwrap with active privkey. **Carve-out**: rotation only. Normal paths use `group_session_open` instead.|
|`dek_rewrap_with_old_key`|`challenge_token`, `signature`, `recovery_handle`, `encrypted_group_dek`, `new_public_key`, `server_key_version?`|`{ new_encrypted_group_dek }`|Synthetic action — unwrap+wrap in Keeper. raw bytes never leave (R4 fix-forward).|
|`group_dek_generate_and_open`|`my_public_key`|`{ group_handle, expires_at_ms, encrypted_for_me_b64 }`|Generate new 32B Group DEK + register as session + RSA-wrap with caller pubkey. raw never leaves.|
|`dek_rewrap_for_member`|`wrapped_for_me_b64`, `other_public_key`|`{ encrypted_for_other_b64 }`|Synthetic unwrap+wrap. raw stays in Keeper memory only.|
|`dek_unwrap_and_rewrap_for_many`|`wrapped_for_me_b64`, `recipient_public_keys[]`|`{ encrypted_for_recipients_b64[] }`|Multi-recipient variant of `dek_rewrap_for_member`. Unwrap my wrapped Group DEK once, RSA-OAEP re-wrap to each recipient key; response list is parallel to the request keys. raw unwrapped once, stays in Keeper memory only. Used by `adminRotateDek` to wrap the OLD Group DEK to every member + the archive key without the raw entering the JS heap.|

### Group session (Phase 12c)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`group_session_open`|`encrypted_group_dek`|`{ group_handle, expires_at_ms }`|Unwrap with active privkey, store in memguard, return opaque handle.|
|`group_session_open_with_raw`|`group_dek_b64`|`{ group_handle, expires_at_ms }`|**DEK rotation escape hatch** — accept raw 32B Base64 directly. Normal paths must use `group_session_open`.|
|`group_session_close`|`group_handle`|_empty_|Discard. Idempotent.|
|`group_session_status`|`group_handle`|`{ exists, remaining_ms }`|Diagnostic. `remaining_ms` is TTL until reaper purges; `0` for unknown/expired handles.|

### Item DEK / drag (Phase 12b)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`aes_generate_and_wrap`|`group_handle`|`{ item_dek_raw_b64, wrapped_item_dek }`|Generate new 32B Item DEK + Group-DEK-wrap. `wrapped_item_dek` = Base64(IV(12)‖ciphertext).|
|`aes_unwrap_and_encrypt`|`wrapped_item_dek`, `group_handle`, `plaintext_b64`|`{ iv_b64, ciphertext_b64 }`|Decrypt Item DEK in Keeper, AES-GCM encrypt plaintext.|
|`aes_rewrap`|`wrapped_item_dek`, `src_group_handle`, `dst_group_handle`|`{ wrapped_item_dek }`|Cross-group share. raw Item DEK in Keeper memory only.|
|`aes_unshare_rewrap_meta`|`wrapped_item_dek`, `src_group_handle`, `iv_b64`, `ciphertext_b64`, `meta_fields` (key→Base64(IV‖ct)), `extra_dst_group_handles[]`|`{ new_encrypted_value, new_encrypted_fields, new_grants[] }`|UNSHARE_REENCRYPT synthetic — OLD Item DEK unwrap → decrypt value/meta → generate new Item DEK → re-encrypt + wrap to N groups. plaintext echoed 0 times.|
|`aes_unwrap_and_decrypt_meta`|`wrapped_item_dek`, `group_handle`, `meta_fields` (key→Base64(IV‖ct))|`{ fields }` (key→plaintext UTF-8)|Bulk decrypt of group entry meta fields. plaintext metadata carve-out — value plaintext echoed 0 times (use the separate *_to_clipboard action).|

### Personal DEK (Phase 12d)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`dek_generate_and_wrap_password`|`password`|`{ encrypted_dek_b64 }`|PBKDF2 → KEK → AES-wrap new DEK. Signup. Output = Base64(salt(16)‖iv(12)‖ct).|
|`dek_generate_and_wrap_dual`|`password`|`{ password_wrapped_dek_b64, device_wrapped_dek_b64 }`|Dual wrap (password + deviceKey). Signup. Server form Base64(salt(16)‖iv(12)‖ct); local form Base64(iv(12)‖ct). deviceKey is fetched from Keychain inside Keeper (Keeper 0.0.8 fix-forward — never crosses IPC).|
|`dek_rotate_to_device_key`|`password`, `encrypted_dek_b64`|`{ device_wrapped_dek_b64 }`|Login: re-wrap server password-wrap with deviceKey. deviceKey from Keychain.|
|`dek_unwrap_and_encrypt`|`encrypted_dek_b64`, `plaintext_b64`|`{ iv_b64, ciphertext_b64 }`|Personal scope encrypt. deviceKey from Keychain.|
|`dek_unwrap_and_decrypt_meta`|`encrypted_dek_b64`, `meta_fields` (key→Base64(IV‖ct))|`{ fields }` (key→plaintext UTF-8)|Bulk decrypt of personal entry meta fields. plaintext metadata carve-out — value plaintext echoed 0 times.|

> **Removed (Keeper 0.0.21):** `aes_unwrap_and_decrypt` / `dek_unwrap_and_decrypt` — the plaintext-returning actions have been removed from dispatcher / proto / handler entirely. User-visible decryption uses `*_unwrap_and_decrypt_to_clipboard` (clipboard sink), and UI meta display uses `*_unwrap_and_decrypt_meta` (metadata carve-out). Follow-up to

### Decrypt-to-clipboard (Keeper-owned plaintext sink)

Keeper owns the plaintext sink: it decrypts in process memory and writes the plaintext directly to the OS clipboard via `Deps.Clipboard`. Responses carry no plaintext / `plaintext_b64` / preview / length metadata. `clipboard_ttl_ms` must be in `[5000, 60000]`.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`aes_unwrap_and_decrypt_to_clipboard`|`wrapped_item_dek`, `group_handle`, `iv_b64` (12B), `ciphertext_b64`, `clipboard_ttl_ms`|`{ copied, clipboard_ttl_ms }`|Group decrypt → Keeper clipboard. No plaintext echoed.|
|`dek_unwrap_and_decrypt_to_clipboard`|`encrypted_dek_b64`, `iv_b64` (12B), `ciphertext_b64`, `clipboard_ttl_ms`|`{ copied, clipboard_ttl_ms }`|Personal decrypt → Keeper clipboard. deviceKey from Keychain. No plaintext echoed.|
|`group_decrypt_to_clipboard`|`group_handle`, `iv_b64` (12B), `ciphertext_b64`, `clipboard_ttl_ms`|`{ copied, clipboard_ttl_ms }`|Drag/audit token (raw Group DEK direct) → Keeper clipboard. No Item DEK indirection. No plaintext echoed. Follow-up to|

Default `Deps.Clipboard` is the production OS clipboard backend. If backend initialization fails, Keeper uses an explicit unavailable clipboard fallback whose writes fail; copy actions must not report `{ copied: true }` unless the clipboard write succeeded. Tests inject `clipboard.MemoryClipboard` for SHA-256-hash-based assertions without storing plaintext in the fake.

### Guest share (external share re-encryption)

Sibling to the decrypt-to-clipboard family with a different sink. Instead of writing plaintext to the clipboard, the Keeper re-encrypts the token under a fresh one-time guest key K so the org token can be shared externally without the plaintext ever entering the Extension JS heap. The response carries only the guest ciphertext + K — never plaintext or the raw Group DEK.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`group_transcrypt_for_guest`|`group_handle`, `iv_b64` (12B), `ciphertext_b64`, `passphrase?`, `passphrase_salt?` (Base64)|`{ guest_ciphertext, guest_key }`|Decrypt an org Group-DEK token in Keeper memory, re-encrypt under a random 32B guest key K, zeroize plaintext. `guest_ciphertext` = standard Base64 of IV(12)‖AES-GCM(ct‖tag); `guest_key` = Base64URL(no pad) of K. No plaintext / Group DEK echoed.|

Output is byte-compatible with the admin SPA guest viewer (`app/src/shared/lib/guest-share-crypto.ts`). AES key = K alone when no passphrase; otherwise `HKDF-SHA256(ikm = K ‖ PBKDF2-SHA256(passphrase, salt, 200000, 32B), salt = salt, info = "dragpass-guest-v1", 32B)`. `passphrase` and `passphrase_salt` are provided together or neither — the app generates the salt (standard Base64) and stores it server-side, so only `guest_ciphertext` + `guest_key` come back.

## Error codes

The `error_code` field on failure responses carries a coarse category token
that the Extension can branch on without parsing the human-readable `error`
message. Codes are stable enums; messages are not.

|Code|Trigger|Extension reaction|
|---|---|---|
|`validation_error`|Payload format / length / required-field check failed (see `validation.go`).|Bug — surface as developer error, no retry.|
|`not_found`|Requested resource missing (Keychain secret slot, session handle, server key version).|Re-bootstrap / re-login / refresh server keys + retry once.|
|`expired_session`|TTL expired on a Keeper session handle (`recovery_session_*`, `group_session_*`).|Open a fresh session and retry the original action.|
|`crypto_failure`|AES-GCM unwrap, RSA-OAEP, or signature verification failed.|Hard fail — payload was tampered or wrong key. No retry.|
|`storage_failure`|OS Keychain access denied / file permission.|Surface to user as a permission prompt.|
|`unsupported`|Unknown `action` name, or protocol version mismatch.|Prompt user to upgrade Keeper.|
|`internal_error`|Unexpected error not covered by the above.|Bug — capture for diagnostics.|

The `error` string is sanitized but **may include field names** (e.g.
`wrap_key_b64: must be 32 bytes`). It never includes secret values. Mapping
between Go sentinel errors and codes lives in `internal/keystore/errs/errs.go`
(`CodeForError`):

- `*ValidationError` → `validation_error`
- `ErrSecretNotFound` / `ErrServerKeyVersionNotFound` / `ErrNoActiveServerKey` /
  `ErrRecoverySessionNotFound` / `ErrGroupSessionNotFound` → `not_found`
- `ErrRecoverySessionExpired` / `ErrGroupSessionExpired` → `expired_session`
- All other errors → `internal_error`

`crypto_failure`, `storage_failure`, and `unsupported` are not auto-mapped —
the handler that detects the failure assigns them explicitly via
`errorCodeResponse(...)`.

The `error_code` field is `omitempty` in the response envelope — older Keeper
builds (pre-Wave 7 P2) returned only the human-readable `error` string. The
Extension treats absence as `internal_error` for branching purposes.

## Versioning

|Keeper version|New / changed actions|Notes|
|---|---|---|
|0.0.6|`aes_*` (4) + `dek_*` (5 personal)|Phase 12 Zero-Extractable first cut.|
|0.0.7|`dek_rewrap_with_old_key`|Recovery raw exposure fix-forward.|
|0.0.8|`dek_*` shape change (deviceKey from Keychain, no IPC)|2 fix-forward.|
|0.0.9|`aes_*` shape: `group_dek_b64` → `group_handle`. New `group_session_*` (4).|Phase 12c opaque handle.|
|0.0.10|`recovery_session_open`/`_close`. `recoverysign`/`dek_rewrap_with_old_key` accept `recovery_handle`.|§3 mitigation — PEM held in Keeper memguard.|
|0.0.11|`group_dek_generate_and_open`, `dek_rewrap_for_member`|Admin path raw-free synthetic actions.|
|0.0.12|`refresh_server_keys`|Phase 13b multi-version server keys.|
|0.0.13|`rotate_user_keypair_prepare`/`_promote`|Phase 13e voluntary user key rotation.|
|0.0.14|`rotate_device_key`|Phase 13f voluntary device key rotation.|
|0.0.15|`rotate_user_keypair_status`/`_abort`|Phase 14a stuck recovery.|
|0.0.16|`rotate_user_keypair_promote` request adds `confirmation_payload`|Bind confirmation to pending key + Keeper-side TTL.|
|0.0.17|Remove `unwrapgroupdekwithkey` dispatch/export|Close legacy Recovery raw PEM IPC path; use `recovery_session_open` + `dek_rewrap_with_old_key`.|
|0.0.18|`aes_unwrap_and_decrypt_to_clipboard` / `dek_unwrap_and_decrypt_to_clipboard` activated|Phase 1 decrypt-to-clipboard cutover. RegistryList copy flow now delegates to Keeper-owned OS clipboard. Plaintext leaves Native Messaging response.|
|0.0.19|`aes_unshare_rewrap_meta`, `aes_unwrap_and_decrypt_meta`, `dek_unwrap_and_decrypt_meta`| UNSHARE_REENCRYPT synthetic action + two bulk meta-field decrypt actions (group/personal). value plaintext is only via the separate `*_to_clipboard` actions — meta responses contain plaintext metadata but secret values 0 times.|
|0.0.20|`group_decrypt_to_clipboard`|Writes plaintext from drag/audit tokens (encrypted directly with the raw Group DEK) directly to the Keeper-owned OS clipboard. Used in the context menu / the group branch of `REGISTRY_DECRYPT` — limited to normal mode + current-version DEK tokens (audit / older versions remain on the old `decryptWithGroupDEK` plaintext fallback, cutover in a later phase).|
|0.0.21|Remove `aes_unwrap_and_decrypt` / `dek_unwrap_and_decrypt`|The two plaintext-returning actions are removed from dispatcher / proto / handler entirely. User-visible decryption always uses the clipboard sink, UI meta uses the `*_unwrap_and_decrypt_meta` carve-out action — the surface where plaintext values could be included in the Native Messaging response envelope is fully closed at the dispatcher boundary. The e2e verification pattern has been migrated to `*_to_clipboard` + `KEEPER_GET_CLIPBOARD_HASH_E2E` SHA-256 comparison (see clipboard-copy.test.ts).|
|0.0.1|Version epoch reset|Release numbering restarted at 0.0.1 when the project moved to its public home (github.com/dragpass/keeper). No protocol change — 0.0.1 speaks the same protocol as the last pre-reset version (0.0.21 line above).|
|0.0.2|`reset_device_identity`|Local self-recovery action wiping this device's account-scoped key material after a server-side account/DB reset.|
|0.0.3|`group_transcrypt_for_guest`|Re-encrypts an org Group-DEK token into an external guest share (fresh one-time key K, optional passphrase HKDF) entirely inside Keeper memory. Byte-compatible with the admin SPA guest viewer. Plaintext / Group DEK never enter the JS heap.|
|0.0.4|`archive_key_generate` / `archive_key_status`|Per-org break-glass Archive / Recovery keypair (RSA-2048) in a dedicated Keychain slot. Used only to additionally wrap OLD Group DEKs during rotation (`org_owner_archive` grant). Both actions are best-effort from the Extension's side — an older Keeper returns `unsupported`, in which case archive wrapping is silently skipped.|
|0.0.5|`archive_unwrap_and_rewrap`|Break-glass re-grant composite. Unwraps an OLD Group DEK from the `org_owner_archive` grant with the archive private key and re-wraps it to a target member's public key, entirely inside Keeper memory (raw-free, same pattern as `dek_rewrap_for_member`). Best-effort from the Extension's side — an older Keeper returns `unsupported`, in which case the break-glass re-grant flow surfaces a "upgrade Keeper" notice.|
|0.0.6|`dek_unwrap_and_rewrap_for_many`|Multi-recipient variant of `dek_rewrap_for_member`. Unwraps the OLD Group DEK once and re-wraps it to every member + the org archive key in one round-trip, so `adminRotateDek` (and the auto-rotation scheduler) no longer unwrap the OLD raw into the Extension JS heap. (The pre-existing per-member unwrap→JS→wrap fallback for older Keepers was removed on the Extension side — rotation now fails with `keeper:unsupported` rather than routing the raw OLD DEK through the JS heap.)|
|0.0.7 (current)|`archive_key_split`, `archive_share_rewrap`, `archive_session_begin`/`_end`, `archive_quorum_combine_and_rewrap`|Archive-key admin quorum (Shamir N-of-M break-glass). Splits the org archive private key across M admin devices (in-repo GF(2^8) Shamir, hybrid RSA-OAEP+AES-GCM share wrap) and deletes the whole key; break-glass reconstructs it only inside the coordinator's Keeper during an N-approval recovery session, wiping all key material before returning only the re-granted wraps.|

The Extension enforces `MIN_KEEPER_VERSION` (currently `"0.0.1"`, the first
release of the public version epoch). Keeper-down or below-min sets a red
`'!'` badge and blocks crypto actions until the user upgrades.

The `error_code` response field (Wave 7 P2 Error Taxonomy) was added without
a Keeper version bump — it is `omitempty`, so older Extensions that don't
read the field continue to work against newer Keeper builds, and older Keeper
builds that don't emit it continue to work against newer Extensions.

## Adding a new action

1. Add the action name constant to `internal/keystore/proto/actions.go` with a
   doc-comment that explains intent + security model.
2. Define `<Name>Request` / `<Name>ResponseData` in `internal/keystore/proto/`.
3. Implement `Validate()` on the request using helpers from `validation.go`
   (`requireString`, `requireBase64`, `requireHandle`, etc.).
4. Implement the handler as an `*App` method in the appropriate domain file
   (`internal/keystore/handlers/identity.go`, `dek.go`, `group_session.go`, etc.). Wrap
   secrets in `memguard.NewBufferFromBytes` and `defer Destroy`. Add a free
   function wrapper `func HandleX(req XRequest) BaseResponse { return DefaultApp().HandleX(req) }`
   for dispatcher / backward-compat callers.
5. Register the handler in the `dispatch` package registry map using
   `wrap((*App).HandleX)` (Go method value form — propagates injected `*App`).
6. Add a row to the matching table in this file (action catalog) and
   bump the Extension's `MIN_KEEPER_VERSION` gate
   if the Extension cannot run on older Keeper.
7. Add a positive + negative unit test in
   `internal/keystore/<file>_test.go`. For sensitive fields, add a regression
   guard that verifies the value is not echoed in `error` strings or logger
   messages (see `MemoryLogger.Contains` patterns in `*_app_test.go`).

## References

- `internal/keystore/proto/actions.go` — action name constants.
- `internal/keystore/proto/` — request / response types and `Validate()`.
- `internal/keystore/dispatch/dispatch.go` — action → handler routing.
- `internal/keystore/proto/validation.go` — request validation helpers.
- `internal/keystore/errs/errs.go` — `ErrorCode` enum + `CodeForError` mapping.
- `internal/keystore/handlers/refresh_server_keys.go` — `SystemServerKeyEntry` shape.
