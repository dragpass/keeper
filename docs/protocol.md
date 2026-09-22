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
`auth_recovery_prepare`, `dek_rewrap_with_old_key`,
`rotate_user_keypair_prepare`, `rotate_user_keypair_promote`.

## Sensitive payload classification

Fields are classified according to their leakage cost. Treat the classification
as a contract:

|Class|Examples|Logging|
|---|---|---|
|`secret`|`password`, `passphrase`, raw DEK Base64 (`group_dek_b64`, `item_dek_raw_b64`), `plaintext_b64`, `wrap_key_b64`|Never log|
|`wrapped`|`wrapped_item_dek`, `encrypted_dek_b64`, `wrapped_keeper`, `wrapped_keeper_b64`, `encrypted_group_dek`, `wrapped_for_me_b64`, `wrapped_for_archive_b64`, `encrypted_for_other_b64`, `device_wrapped_dek_b64`, `password_wrapped_dek_b64`|Never log|
|`handle`|`group_handle`, `recovery_handle`, `entered_recovery_key_handle`, `src_group_handle`, `dst_group_handle` (32B random ID)|OK to log|
|`metadata`|`server_key_version`, `request_id`, `expires_at_ms`, `remaining_ms`, `version`, `payload_kind`|OK to log|
|`public material`|`publickey`, `recipient_public_key`, `my_public_key`, `other_public_key`, `new_public_key`, `iv_b64`, `ciphertext_b64` (already enc), `challenge_token`, `signature` (Base64 over public token), `fingerprint` / `old_fingerprint` / `new_fingerprint` (hash of a public key), `old_signature` / `new_signature` (statement signatures), `rotation_statements` (public keys + signatures over them)|OK to log|
|`metadata`|`state`, `first_seen_at`, `last_seen_at`, `verified_at`, `pin_enforced`, `pin_state`, `pin_states`, `advanced`, `reset`, `owner_account_id`, `account_id`|OK to log, but never the whole pin list — the set of peers an account has observed is a social graph even though each fingerprint is harmless. `owner_account_id` is metadata by class, but the owner check logs neither the recorded id nor the rejected one: the recorded one is what a caller probing for the namespace would want back|
|`metadata`|`epoch`, `chain_index`, `first_chain_index`, `count`, `generation`, `sender_leaf_index`, `content_type`, `client_message_id`, `first_delivery`, `stored`, `removed_conversations`, `watermark_epoch`, `watermark_leaf_index`, `watermark_next_handshake`, `watermark_next_application`|OK to log, but the conversation-state path deliberately logs none of them: it emits a stage name and an error code and nothing else. Chain counters carry no key material and have real diagnostic value, which is exactly why the line between diagnostics and state is drawn in code rather than left to judgement (ADR §4.3).|

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

The current production backend is macOS Cocoa. Keeper exposes no approval or
confirmation action. Native UI is limited to recovery-key display through
composite auth actions that return encrypted or public material rather than RK24 text.

### Device key (per-device wrap layer)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`getdevicekey`|_empty_|`{ key }`|Fetch deviceKey from OS Keychain. `key` = Base64(raw 32B).|
|`savedevicekey`|`key`|_empty_|Save deviceKey. `key` = Base64(raw 32B). Used during signup.|
|`deletedevicekey`|_empty_|_empty_|Remove deviceKey from Keychain (account reset).|
|`reset_device_identity`|_empty_|`{ cleared }`|Local self-recovery: wipe this device's account-scoped key material — active keypair (`keeper_private_key`/`keeper_public_key`), pending keypair (`pending_keeper_private_key`/`pending_keeper_public_key`), `session_code`, `device_key` — plus every owner's chat state (the sealed files, the anchors, and the seal keys), so the user can re-enroll after a server-side account/DB reset. `cleared` = names of slots actually removed (idempotent: `[]` when nothing was present). `server_public_key` is preserved (account-independent trust anchor). Returns no key material.|
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
|`auth_signup_prepare`|`alias`, `password`, `recovery_key`|`{ password_wrapped_dek_b64, device_wrapped_dek_b64, recovery_auth_seed, recovery_wrapped_keeper, recovery_key_version, signature, publickey }`|App-first signup composite. The App supplies the password and newly generated RK24 as request-only fields. Keeper creates both DEK wraps and the identity keypair and returns only encrypted or public material.|
|`auth_recovery_reissue_prepare`|`alias`, `recovery_key`|`{ recovery_auth_seed, recovery_wrapped_keeper, recovery_key_version }`|Derives replacement recovery material from a request-only RK24 and rewraps the active private key. The response contains only server-storable material.|
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
|`archive_unwrap_and_rewrap`|`wrapped_for_archive_b64`, `recipient_public_key`|`{ encrypted_for_other_b64 }`|Break-glass re-grant composite. Unwrap an OLD Group DEK wrapped to the archive public key (`org_owner_archive` grant) with the archive private key → RSA-OAEP re-wrap to a target member's public key. raw Group DEK lives only in Keeper memory (memguard); the response carries only the new wrap. Unwrap tries the org slot first and falls back to the **account archive slot** on decrypt failure — after an ownership handoff, grants are wrapped to the new owner's account directory key. Both slots empty → `not_found`. Same raw-free pattern as `dek_rewrap_for_member`.|
|`archive_key_rotate_begin`|_empty_|`{ publickey, fingerprint }`|Same-device rotation, step 1. Generate a NEW archive keypair into the **staging** slot (`org_archive_private_key_staging`) and return its public key + fingerprint. The **active** slot is left untouched, so `archive_unwrap_and_rewrap` keeps unwrapping with the OLD active key until commit — the caller re-wraps every existing grant to this new `publickey` first. `archive_key_generate` is idempotent and can't do this on the same device. Any abandoned staging is wiped and replaced. No active key present → `validation_error` (first-time enable is `archive_key_generate`, not a rotation).|
|`archive_key_rotate_commit`|_empty_|`{ fingerprint }`|Same-device rotation, step 2. Promote the staged keypair to the active slot; the Save over the active private-key slot replaces (wipes) the old active private key at rest. Clears the staging slot. Returns the promoted (now active) key `fingerprint`. No staging present → `not_found`.|
|`archive_key_rotate_abort`|_empty_|`{ aborted }`|Discard the staging slot without touching the active key. `aborted=true` when a staged key was cleared, `false` when there was none (no-op success). Cleanup for a rotation that was never committed.|

#### Per-account Archive / Recovery receiving keypair

A second, independent archive keypair in its own slots
(`account_archive_private_key` / `account_archive_public_key`). Its public
half is what the account publishes to the server account directory
(`account_archive_keys`) so the account can RECEIVE material wrapped to it:
ownership-handoff re-wrapped grants and archive quorum Shamir shares. It is
deliberately not the org archive keypair — `archive_key_split` deletes the org
private key when quorum is enabled, and the account receiving key must survive
that wipe. Kept as separate actions (rather than a slot parameter on
`archive_key_*`) because the two keys have different lifecycles.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`account_archive_key_generate`|_empty_|`{ publickey, fingerprint }`|Generate an RSA account archive keypair if none exists; idempotently return only its metadata otherwise. Same contract as `archive_key_generate`, against the account slot.|
|`account_archive_key_status`|_empty_|`{ has_active, publickey?, fingerprint? }`|Whether an account archive key exists + the public key.|

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
|`archive_key_split`|`threshold_n`, `recipient_public_keys[]` (M admin account archive PEMs)|`{ key_fingerprint, shares: [{ share_index, wrapped_key, ciphertext, recipient_fingerprint }] }`|Shamir-split the ORG archive private key into M shares (threshold N), hybrid-wrap share _i_ to `recipient_public_keys[i]`, then **delete** the org archive private key (kept: the org public key; the account archive slot is never touched). `key_fingerprint` is derived from the private key being split so the server can verify the coordinator split the org's actual active archive key. Not idempotent — a missing private key → `not_found`.|
|`archive_share_rewrap`|`wrapped_key`, `ciphertext`, `session_public_key`|`{ wrapped_key, ciphertext }`|An approving admin re-wraps their own share from their ACCOUNT archive key (the dedicated account slot — the key the share was wrapped to at split time; the org slot is not consulted) to the recovery session public key. Distinct from `archive_unwrap_and_rewrap` because shares are hybrid envelopes, not 32-byte DEKs. Missing account archive slot → `not_found`.|
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
|`rotate_user_keypair_prepare`|`challenge_token`, `server_signature`, `server_key_version?`, `account_id`, `reason`, `rotated_at`|`{ new_public_key, old_signature, new_signature, rotation_statement }`|Generate pending keypair, sign challenge with both OLD and NEW privkeys. ACTIVE remains OLD until promote. The three account key trust fields are **required** (0.0.31): a rotation with no statement leaves every peer holding a pin nothing explains, which turns their next wrap into `peer_key_changed`, so there is no path through this action that rotates without one. `reason` is `voluntary` or `compromise` — `recovery` belongs to the recovery flow and is not selectable here. `rotated_at` more than 300s ahead of the Keeper clock is `validation_error`; backdating is allowed, since the server records its own receipt time. The two challenge signatures are unchanged; `rotation_statement` is a separate signature over the §5 canonical, for peers who never see the challenge.|
|`rotate_user_keypair_promote`|`confirmation_token`, `confirmation_payload`, `confirmation_signature`, `server_key_version?`|`{ promoted, active_public_key }`|Verify signed confirmation payload, check pending public key hash/expiry, promote pending → active.|
|`rotate_user_keypair_status`|_empty_|`{ has_pending, pending_public_key, active_public_key }`|Diagnose stuck state (Phase 14a).|
|`rotate_user_keypair_abort`|_empty_|`{ aborted }`|Discard pending slot (Phase 14a). `aborted=false` when neither slot existed (idempotent).|

### Recovery (Phase 2)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`recoverysign`|`challenge_token`, `signature`, `recovery_handle`, `server_key_version?`|`{ signature }`|Sign challenge with recovered OLD private key (PEM held in Keeper memguard via handle). `signature` (request) = server signature over `challenge_token`. `signature` (response) = OLD privkey signature over `challenge_token`.|
|`generatekeypairwithrecoverywrap`|`challenge_token`, `signature`, `wrap_key_b64`, `server_key_version?`, `account_id`, `rotated_at`, `recovery_handle`|`{ publickey, wrapped_keeper, rotation_statement }`|New keypair + AES-GCM-wrap private key with RK24-derived `wrap_key`. `wrapped_keeper` = Base64(IV‖ciphertext). Also produces a rotation statement with `reason` fixed to `recovery` (0.0.31) — the caller cannot choose it. `rotated_at` more than 300s ahead of the Keeper clock is `validation_error`, refused before the statement is built and before the new keypair reaches the Keychain, so the account is left exactly as it was. RK24 recovery changes `accounts.public_key`, so without a statement an ordinary recovery would drop every observer's pin to `changed`. The OLD half is signed through `recovery_handle`, which already points at the OLD private key in memguard; the OLD public key is derived from that same private key rather than read from the Keychain, so the statement describes the key the recovery actually restored. The statement is built before the Keychain is touched.|
|`recovery_session_open`|`challenge_token`, `signature`, `wrapped_keeper_b64`, `wrap_key_b64`, `server_key_version?`|`{ recovery_handle, expires_at_ms }`|Verify challenge, decrypt PEM into memguard, return opaque handle. PEM never crosses IPC.|
|`recovery_session_close`|`recovery_handle`|_empty_|Discard handle. Idempotent (no error if handle absent).|
|`auth_recovery_begin`|`alias`, `recovery_key`|`{ recovery_auth_seed, entered_recovery_key_handle, entered_recovery_key_expires_at_ms }`|Accepts the RK24 entered in the App, derives only the server authentication seed, and immediately stores the RK24 behind an opaque short-lived handle for the prepare step. The response never contains RK24 or its wrap key.|
|`auth_recovery_prepare`|`alias`, `entered_recovery_key_handle`, `challenge_token`, `signature`, `wrapped_keeper_b64`, `recovery_key_version`, `server_key_version?`, `new_recovery_key`, `account_id`, `rotated_at`|`{ old_challenge_signature, recovery_handle, recovery_expires_at_ms, new_publickey, new_recovery_auth_seed, new_recovery_wrapped_keeper, new_recovery_key_version, rotation_statement }`|Verifies the server-signed recovery challenge, restores the old private key into a recovery session, and derives the replacement identity material from a request-only new RK24. Forwards `account_id` / `rotated_at` to the keypair step and returns its `rotation_statement` (0.0.31). The same 300s `rotated_at` bound applies and is checked before the recovery session opens, so a refused date does not consume the entered-key handle. There is no `recovery_handle` on this request surface: the composite opens its own session and uses that handle, so there is nothing for a caller to substitute.|

### Group DEK

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`dek_rewrap_with_old_key`|`challenge_token`, `signature`, `recovery_handle`, `encrypted_group_dek`, `new_public_key`, `server_key_version?`|`{ new_encrypted_group_dek }`|Synthetic action — unwrap+wrap in Keeper. raw bytes never leave (R4 fix-forward).|
|`group_dek_generate_and_open`|`my_public_key`|`{ group_handle, expires_at_ms, encrypted_for_me_b64 }`|Generate new 32B Group DEK + register as session + RSA-wrap with caller pubkey. raw never leaves.|
|`dek_rewrap_for_member`|`wrapped_for_me_b64`, `other_public_key`, `owner_account_id?`, `other_account_id?`, `rotation_statements?`|`{ encrypted_for_other_b64, pin_enforced, pin_state? }`|Synthetic unwrap+wrap. raw stays in Keeper memory only. When `other_account_id` is present the peer key pin is checked before anything is unwrapped (0.0.31): an unexplained key change closes the action with `peer_key_changed` and no wrap output. The two account ids travel together or not at all; sending one without the other is `validation_error`. Request capped at 512 KiB before decode.|
|`dek_unwrap_and_rewrap_for_many`|`wrapped_for_me_b64`, exactly one of `recipients[]` (`{ account_id?, public_key, rotation_statements? }`) or `recipient_public_keys[]`; `owner_account_id?`|`{ encrypted_for_recipients_b64[], pin_enforced, pin_states[]? }`|Multi-recipient variant of `dek_rewrap_for_member`. Unwrap my wrapped Group DEK once, RSA-OAEP re-wrap to each recipient key; response lists are parallel to the request recipients. raw unwrapped once, stays in Keeper memory only. Used by `adminRotateDek` to wrap the OLD Group DEK to every member + the archive key without the raw entering the JS heap. `recipients[]` is the pin-enforced shape (0.0.31); `recipient_public_keys[]` is the pre-0.0.31 flat list, still accepted and never enforced. Sending both, or neither, is `validation_error`. **Every recipient is judged before the first wrap**, so one `peer_key_changed` refuses the whole batch with no partial output — a rotation that wrapped some members and refused others would split the org. A recipient with no `account_id` reports `exempt` (the org archive key is a resource, not an account); several exempt recipients in one call are fine, but a non-empty `account_id` may not repeat, since the parallel lists would report two states for one peer and the second check would judge the first one's freshly written pin. Max 64 recipients, 32 statements each, 512 KiB per request.|
|`group_encrypt`|`group_handle`, `plaintext_b64`|`{ iv_b64, ciphertext_b64 }`|AES-GCM seal plaintext directly under the raw Group DEK behind the handle. Encrypt-direction mirror of `group_decrypt_to_clipboard`. `plaintext_b64` is `secret`; the `iv_b64` / `ciphertext_b64` response is public material. plaintext / raw Group DEK echoed 0 times.|
|`group_encrypt_with_aad`|`group_handle`, `plaintext_b64`, `aad_b64`|`{ iv_b64, ciphertext_b64 }`|AAD-binding variant of `group_encrypt`. Binds the caller-supplied `aad_b64` (canonical context `scope_id\|entry_id\|payload_kind\|schema_version\|dek_version`; `scope_id` is `org_id` for org scope and `account_id` for personal scope, and the org serialisation is byte-identical to the older `org_id` form) into the GCM tag, so a ciphertext cannot be opened under a different context — a swap guard for sealed credential payloads. `aad_b64` is **required** (empty is what `group_encrypt` covers) and is public context material, not secret. Open with the byte-identical AAD to decrypt. `plaintext_b64` is `secret`; response is public material. plaintext / raw Group DEK echoed 0 times.|
|`dek_unwrap_and_encrypt_with_aad`|`encrypted_dek_b64`, `plaintext_b64`, `aad_b64`|`{ iv_b64, ciphertext_b64 }`|Personal-scope sibling of `group_encrypt_with_aad`. Unwraps the device-wrapped personal DEK (device key from the Keychain, never IPC) and seals under it while binding the caller-supplied `aad_b64` (canonical context `account_id\|entry_id\|payload_kind\|schema_version\|dek_version`) into the GCM tag. Same swap guard, different key source. `aad_b64` is **required** (empty is what `dek_unwrap_and_encrypt` covers) and is public context material. `plaintext_b64` is `secret`; response is public material. plaintext / raw DEK echoed 0 times.|
|`group_encrypt_meta`|`group_handle`, `fields` (key→plaintext UTF-8)|`{ meta_fields }` (key→Base64(IV(12)‖ct))|Batch metadata encrypt directly under the raw Group DEK. Metadata-path mirror of `group_encrypt`. Empty plaintext values are skipped (no ciphertext). Output `meta_fields` is directly feedable into `group_decrypt_meta` and uses the combined form the Extension stores per meta field. `fields` are `secret` in the request only; plaintext / raw Group DEK echoed 0 times.|
|`group_decrypt_meta`|`group_handle`, `meta_fields` (key→Base64(IV(12)‖ct))|`{ fields }` (key→plaintext UTF-8)|Batch metadata decrypt directly under the raw Group DEK. Plaintext metadata carve-out; value plaintext echoed 0 times (use `group_decrypt_to_clipboard`). Empty ciphertext values are skipped; a single bad ciphertext fails the whole batch.|

### Group session (Phase 12c)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`group_session_open`|`encrypted_group_dek`|`{ group_handle, expires_at_ms }`|Unwrap with active privkey, store in memguard, return opaque handle. The only Group DEK open path — raw Group DEK never crosses IPC.|
|`group_session_close`|`group_handle`|_empty_|Discard. Idempotent.|
|`group_session_status`|`group_handle`|`{ exists, remaining_ms }`|Diagnostic. `remaining_ms` is TTL until reaper purges; `0` for unknown/expired handles.|

### Credential Control Plane (MCP)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`credential_http_request`|exactly one of `group_handle`, `encrypted_dek_b64`, or `use_local_personal_dek=true`; `iv_b64`, `ciphertext_b64`, `aad_b64`, `target_url`, `method`, `header_template` (placeholders only), `query_template?` (placeholders only), `body_b64?`, signed `policy`|`{ status_code, headers (redacted), body_b64 (redacted), truncated }`|Decrypt-to-tool HTTP sink. The local personal mode reads the device-wrapped personal DEK from the Keeper Keychain, so MCP receives no DEK material. Verifies the RSA-PSS server policy, enforces its exact target and request shape, blocks private-network SSRF and redirects, injects the decrypted credential locally, and returns only a bounded redacted response. `header_template` and `query_template` must each equal the signed policy's copy; at least one of the two must be non-empty. Rendered `query_template` values are appended to `target_url`'s query (`target_url` itself is never substituted) and join the redaction set.|
|`credential_exec_request`|exactly one of `group_handle`, `encrypted_dek_b64`, or `use_local_personal_dek=true`; `iv_b64`, `ciphertext_b64`, `aad_b64`, `executable` (absolute path), `args?` (argv[1:]), `cwd` (absolute, must exist), `env_template` (placeholders only), signed `policy`|`{ exit_code, stdout_b64 (redacted), stderr_b64 (redacted), truncated, timed_out }`|Decrypt-to-tool exec sink (0.0.28). Opens the same sealed payload the HTTP sink opens and injects the decrypted credential into one child process's environment. The signed policy carries `exec_executable` / `exec_argv` / `exec_cwd` / `env_template`, and all four must equal the request exactly or no process starts — there is no network target to pin here, so what the signature binds is the command a human approved. No shell and no PATH lookup (the executable is spawned by absolute path); the child's environment is a fixed allowlist (`PATH HOME USER LOGNAME SHELL LANG LC_ALL TMPDIR TZ TERM`) plus the injected variable, so the caller's own `DRAGPASS_API_TOKEN` never reaches it; the secret goes to the environment and never to argv; the child runs in its own process group killed as a group on the 60s timeout; each stream is capped at 1 MiB with `truncated`; stdout and stderr are masked for any echo of the credential. A non-zero exit is data, not an error — it returns on a successful response. Refused with `unsupported` on Windows, which has no process-group kill.|

### Secure message display (app-display plaintext carve-out)

Two actions, one reveal. `message_display_prepare` validates a message context
and mints a one-shot challenge; `group_decrypt_with_aad_for_app_display`
verifies a server-signed permit over that challenge and returns the plaintext.

This is the protocol's **only** plaintext-returning response and the first
`TestNoRawSecretInResponseTypes` carve-out since 0.0.11. Every clipboard action
still returns no plaintext, and there is no path from this action to the
clipboard. The approved scope of the exception is exactly
`GroupDecryptWithAadForAppDisplayResponseData.plaintext_b64`; the rationale,
exposure table, and invariants live in dragpass-control-plane
`docs/security/secure-message-overlay-proposed-boundary.md`.

What keeps it narrow is that the caller never says how the ciphertext is bound.
There is no `aad_b64`, `domain`, or canonical field in either request: Keeper
builds `dragpass.message|1|<org_id>|<group_id>|<dek_version>|<token_expires_at>`
from the structured fields it validated. A drag token (sealed with no AAD) and a
credential payload (sealed under the credential canonical) therefore fail the
GCM tag here even when the caller holds the right handle and names the right
org, group, and version.

Both requests are decoded strictly — unknown fields, duplicate JSON keys (the
nested `permit` included), missing fields, and payloads over 16 KiB are refused
before anything is opened. The dispatcher's shared decoder cannot refuse a
duplicate key, and a duplicate key in a signature-bound request means verifying
one value and decrypting under another, so these two actions own their decode
(`internal/keystore/handlers/strict_json.go`).

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`message_display_prepare`|`group_handle`, `org_id`, `group_id`, `dek_version`, `message_schema_version` (must be `1`), `token_expires_at`, `audit_table_id` (string or `null`, key required either way), `iv_b64` (12B), `ciphertext_b64` (ciphertext ‖ tag, 17..528B)|`{ challenge }`|Mints 32 CSPRNG bytes as unpadded Base64URL (43 chars) and remembers the whole context plus `SHA256(IV ‖ ciphertext ‖ tag)` (lowercase hex) for 30 seconds. Decrypts nothing; the handle is recorded, not opened. The challenge map is process-local and capped at 8 live entries — a ninth concurrent prepare is refused with `MESSAGE_DISPLAY_BUSY` rather than evicting somebody else's pending reveal. Entries are dropped when they expire, when their group handle is closed (`group_session_close` purges them), and with the process; nothing is persisted.|
|`group_decrypt_with_aad_for_app_display`|the same nine fields, plus `permit`: `{ challenge, account_id, org_id, group_id, dek_version, message_schema_version, token_expires_at, audit_table_id, payload_sha256, issued_at, expires_at, server_key_version, signature }`|`{ plaintext_b64 }`|Opens one message for browser display. `signature` is Base64 RSA-PSS SHA-256 over the 14-item canonical `dragpass.message.display\|1\|challenge\|account_id\|org_id\|group_id\|dek_version\|1\|token_expires_at\|audit_table_id_or_-\|payload_sha256\|issued_at\|expires_at\|server_key_version` (no trailing newline; the schema slot is always `1`; an absent audit table writes `-`), verified under the pinned key of the named version — an unknown version fails closed, never falling back to the active key. The permit, the request, and the remembered challenge must agree field for field including the payload digest; `account_id` has no request counterpart and is held by the signature alone. Window: `issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 30`, plus the challenge's own 30 seconds. `now < token_expires_at` is required with **no** clock grace and re-checked immediately before the response, so a late answer cannot display an expired message. The challenge is then consumed atomically — after the permit verifies, so a bad signature cannot burn somebody's pending reveal, and before the decrypt, so a tag failure cannot be retried against the same authorization. Concurrent replays leave exactly one winner. The plaintext is zeroized after encoding and never logged.|

Domain error codes for these two actions are more specific than the coarse
taxonomy below and travel in the same `error_code` field. They are shared
verbatim with the server and the Extension:

|Code|Trigger|
|---|---|
|`MESSAGE_INVALID_INPUT`|Malformed syntax, wrong size, unknown / duplicate / missing field.|
|`MESSAGE_DISPLAY_BUSY`|The process-local challenge map is full (8 live entries).|
|`MESSAGE_DISPLAY_NOT_AUTHORIZED`|Signature, binding, challenge, permit window, or missing group handle. Deliberately one code for all of them — which check refused is not something an unauthorized caller gets to learn.|
|`MESSAGE_DECRYPT_FAILED`|GCM tag or UTF-8 failure, or a plaintext outside 1..512 bytes.|
|`MESSAGE_EXPIRED`|The message token's own expiry has passed.|

### Conversation chat display (chat reveal carve-out)

One action, one batch, two payload kinds. `conversation_decrypt_batch_for_app_display`
verifies a server-signed read permit and opens a page of one conversation's
messages — 1:1 or named group room — returning the plaintexts parallel to the
request batch. With `payload_kind: "room_name"` (0.0.34) the same action opens
that conversation's single sealed room name instead.

This is the protocol's second `TestNoRawSecretInResponseTypes` carve-out (after
0.0.29's `group_decrypt_with_aad_for_app_display`). Every clipboard action still
returns no plaintext, and there is no path from this action to the clipboard.
The approved scope of the exception is exactly
`ConversationDecryptBatchForAppDisplayResponseData.plaintext_b64` (the `[]string`
element type included); the rationale, exposure table, and invariants live in
dragpass-control-plane
`docs/exec-plans/active/dragpass-chat-1to1-implementation.md` §5 and
`docs/security/threat-model.md` §4.10. 0.0.34 widens what that one entry covers
— N-member rooms, and room names under a second domain — without adding an
entry or a response field; the wider scope is approved in
`docs/exec-plans/active/dragpass-chat-grouproom-implementation.md` §6.2, and the
carve-out's own rationale string is required to name it.

What keeps it narrow is that the caller never says how the ciphertext is bound.
There is no `aad_b64`, `domain`, or canonical field in the request: Keeper builds
`dragpass.chat|1|<org_id>|<conversation_id>|<dek_version>` from the permit's
structured fields. A drag token (no AAD), a Secure Message
(`dragpass.message|...`), and a credential payload (credential canonical)
therefore fail the GCM tag here even when the caller holds the right handle and
names the right conversation.

The one thing the caller may say is `payload_kind`, and it is an enum of two
values rather than a string it composes. Each value selects a **pair** of
canonicals, chosen together inside Keeper:

|`payload_kind`|Permit canonical|AAD|Batch size|
|---|---|---|---|
|`message` (default; also what an omitted field means)|`dragpass.chat.read\|1\|…`|`dragpass.chat\|1\|…`|0..200|
|`room_name`|`dragpass.room.read\|1\|…`|`dragpass.room\|1\|…`|exactly 1|

Because the pair moves together, a message permit presented for a `room_name`
request fails signature verification and a room name fed to a `message` request
fails the GCM tag. Choosing the canonical *is* the binding check; there is no
separate one to forget. Both permits carry the same nine items, the same fixed
300-second window, and no domain field of their own — the domain lives only in
the string the signature covers. `room_name` is capped at one entry because a
room has one name, which also keeps the second domain from becoming a general
batch decrypt. An unknown `payload_kind` is `CHAT_INVALID_INPUT`, never a
silent fallback to `message`. Unlike the Secure Message reveal there is no
per-message challenge and no prepare step: opening the group handle from a
wrapped grant is itself the key-possession proof, so the two axes are
(handle = key) + (permit = server authorization). One permit opens every message
of one conversation at one `dek_version` inside its TTL.

The request is decoded strictly — unknown fields, duplicate JSON keys (the
nested `permit` included), missing fields, a request over 2 MiB, a batch over
200 messages, an unknown `payload_kind`, and a `room_name` batch that is not
exactly one entry are refused before anything is opened, through the same
`internal/keystore/handlers/strict_json.go` the message display actions use.
`payload_kind` is the one optional key on this request: the strict decoder
treats every other field as required, so a caller written against 0.0.33 sends
no `payload_kind` at all and keeps the behavior it was written against.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`conversation_decrypt_batch_for_app_display`|`group_handle`, `permit`: `{ account_id, org_id, conversation_id, dek_version, issued_at, expires_at, server_key_version, signature }`, `org_id`, `conversation_id`, `dek_version`, `payload_kind?` (`message` \| `room_name`, default `message`), `messages`: `[{ iv_b64 (12B), ciphertext_b64 (ciphertext ‖ tag, 17..8208B) }]` (at most 200; exactly 1 when `payload_kind` is `room_name`)|`{ plaintext_b64: string[] }` (parallel to `messages`)|Opens a page of one conversation's messages — or, with `payload_kind: room_name`, that conversation's single sealed room name — for browser display. `payload_kind` selects a permit canonical and an AAD **together**: `message` (the default, and what an omitted field means) takes `dragpass.chat.read\|1\|…` + `dragpass.chat\|1\|…`, `room_name` takes `dragpass.room.read\|1\|…` + `dragpass.room\|1\|…`, and any other value is `CHAT_INVALID_INPUT`. `signature` is Base64 RSA-PSS SHA-256 over the selected 9-item canonical `<domain>\|1\|account_id\|org_id\|conversation_id\|dek_version\|issued_at\|expires_at\|server_key_version` (no trailing newline; the schema slot is always `1`), verified under the pinned key of the named version — an unknown version fails closed, never falling back to the active key. Since neither permit carries a domain field, presenting a message permit for a `room_name` request (or the reverse) simply fails verification; choosing the canonical is the binding check. The request's `org_id` / `conversation_id` / `dek_version` must equal the permit's. Window: `issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 300`, the same for both kinds. The AAD is assembled inside Keeper from the permit's fields, never from the request body. Each message is opened under the conversation DEK behind the group handle; if any message fails the tag / UTF-8 / AAD, the whole batch is refused with `CHAT_DECRYPT_FAILED` and no partial plaintext — one conversation at one version is one key/AAD family, so a failure is a tamper or foreign-ciphertext signal. On success the plaintexts are returned parallel to `messages`, zeroized after encoding and never logged.|

Domain error codes for this action are more specific than the coarse taxonomy
below and travel in the same `error_code` field. They are shared verbatim with
the server and the Extension:

|Code|Trigger|
|---|---|
|`CHAT_INVALID_INPUT`|Malformed syntax, wrong size, unknown / duplicate / missing field, a request over 2 MiB, a batch over 200 messages, a `payload_kind` outside `message` / `room_name`, or a `room_name` batch that is not exactly one entry.|
|`CHAT_PERMIT_NOT_AUTHORIZED`|Permit signature, binding, window, or missing group handle. Deliberately one code for all of them — which check refused is not something an unauthorized caller gets to learn.|
|`CHAT_DECRYPT_FAILED`|A GCM tag / UTF-8 / AAD failure on any message in the batch; the whole batch is refused with no partial plaintext.|

### Conversation state (chat v2 ratchet storage)

Five actions over one sealed directory. They are the durability and
mutual-exclusion layer DragPass chat v2's ratchet will sit on, and **none of
them encrypts anything**. What they decide, durably and under a
per-conversation lock, is which chain position a sender may use next and which
ciphertext a retransmission must reuse. MLS is linked behind the `mls` build
tag and keeps its state in these records, but no action carries any of it in
either direction. Getting "who writes what, when" wrong breaks
forward secrecy no matter which library lands on top, which is why the storage
contract is fixed before the library is chosen.

The design, the alternatives that were rejected, and the gaps it accepts are in
dragpass-control-plane `docs/security/adr-ratchet-state-storage.md` (S1–S7).

**Where the state lives, and the trade.** `keychain.SecretStore` cannot hold
it: its whole interface is `Get` / `Set` / `Delete`, so no primitive changes the
state body and its rollback anchor together; a Windows Credential Manager entry
caps around 2.5 KB, which an MLS group state passes at realistic sizes; and it
cannot enumerate, which logout-time erasure needs. So the keyring keeps only the
two small things — a 32-byte seal key per owner account and a per-conversation
anchor — and the bulk moves to `os.UserConfigDir()/dragpass-keeper/chat-state/`
as owner-only sealed files. **This is a real step down in at-rest protection**: the
bulk is now guarded by file permissions plus the seal key rather than by the OS
keyring, and the files go into backups. The seal key staying in the keyring is
what keeps the files alone worthless, and it is a requirement of the design
rather than a convenience. The file name is an HMAC under a subkey of the seal
key, so neither the directory listing nor a keyring slot name carries a
conversation id — metadata hygiene, not a boundary, and not claimed as one.

**"Owner-only" is built differently on each platform, and it is not a mode
bit everywhere.** On macOS and Linux the files are `0600` and their directories
`0700`. Windows ignores those bits — `os.Chmod` there sets a read-only
attribute and nothing else, so the same call leaves a state file at `0666` and
carrying whatever its parent directory hands down. Since `dragpass-keeper.exe`
is a released artifact, the property is rebuilt on Windows out of what that
platform enforces: each state file and directory gets a DACL holding exactly one
access-allowed entry for the token user, applied with
`PROTECTED_DACL_SECURITY_INFORMATION` so nothing is inherited. The Keeper's own
tests assert this per platform rather than skipping on Windows, the mode bits
through `os.Stat` and the DACL through `GetNamedSecurityInfo`.

**What that buys on either platform is the same, and it is narrower than it
looks.** It keeps *other users of the machine* out of the state directory. It
does **not** separate processes running as the same user: they can read the
file, and they can read the seal key out of the keyring or Credential Manager
too. On Windows the file's owner additionally keeps implicit `WRITE_DAC`, so
same-user code can simply rewrite the ACL — which is the same statement said
from the other side. The file boundary is not a cryptographic boundary on any
platform; what it separates is "can make the Keeper do this" from "can read
these bytes off the disk".

**Four properties the layer owes its caller**, none of which MLS can restore
once broken:

- One conversation is written by one process at a time: an advisory file lock
  per conversation, never a global one, held across the whole read → modify →
  persist → fsync cycle, with nothing cached across it. There is no store-type
  bypass, deliberately — the one in `withPersonalKeyBundleLock` would leave the
  two-process tests running a path with no lock in it and passing.
- A state change is one whole-file replacement: temp file, fsync, rename,
  directory fsync. A crash leaves the old file or the new one. A temp file is
  never a load candidate and is swept when found, which is what makes a
  half-written one harmless. POSIX guarantees the rename; **the Windows
  equivalent is on the ADR's measure-first list and is not assumed**.
- A rewound state is refused, not continued, on two axes. The keyring anchor's
  monotonic `generation` catches a state file restored on its own, since a
  backup that restores the config directory does not restore the login keychain
  with it; the server watermark carried **inside the signed permit** catches a
  file and an anchor restored together. The refusal latches: nothing in the
  Keeper clears it, and the only ways out are a new epoch and
  `chat_state_purge`. There is no "retry anyway", because continuing on a
  rewound chain reuses `(key, nonce)` pairs and that is the one failure here
  that cannot be taken back.
- A chain position is consumed **before** the caller encrypts with it, and the
  ciphertext built from it is stored so a retransmission is the same bytes.

**The server is still UNTRUSTED.** The rule is "follow whichever of the
server's watermark and the local anchor is *higher*, never the lower", and both
move only forward. A server reporting a lower position changes nothing; a
server reporting a higher one can force a re-establishment but learns no
plaintext. The watermark is inside the signature rather than beside it because
a watermark carried as an ordinary request field could simply be omitted by a
caller that would rather not be checked against it. **Accepted gap:** restoring
the file and the anchor from the same moment *and* a cooperating server defeats
both axes. Local state alone cannot close it, and it is recorded rather than
hidden.

**Why every action but `chat_state_purge` demands a server-signed permit.** The
dispatcher has one action registry and the Keeper cannot tell who launched it —
the extension service worker, the popup, `@dragpass/mcp`, and `dragpass-run`
all speak the same protocol to the same binary. "MCP does not call these" is a
code convention, and a convention lasts until the PR that adds a call, which is
not what should stand between a prompt injection and a conversation's chain
state. A permit is issued on user-JWT routes only, and the `/api/v1/mcp/*`
service token cannot reach those routes, so an MCP process that frames these
requests by hand still cannot produce one. **What this does not stop** is a
local attacker who already holds a live user session, the same carve-out the
account key trust contract states about pins. The Keeper half of the boundary
is pinned by a test: the set of actions MCP calls is exactly five (`ping`,
`group_session_open`, `group_session_close`, `credential_http_request`,
`credential_exec_request`) and no `chat_state_*` action is in it.

The permit canonical is its own domain, so a page of chat read permits cannot
also advance a chain and a state permit cannot open a message:

```
dragpass.chat.state|2|<account_id>|<org_id>|<conversation_id>
  |<watermark_epoch>|<watermark_leaf_index>
  |<watermark_next_handshake>|<watermark_next_application>
  |<issued_at>|<expires_at>|<server_key_version>
```

Twelve items joined with `|`, no trailing newline, the schema slot always `2`,
signed RSA-PSS SHA-256 and verified under the pinned key of the named version —
an unknown version fails closed, never falling back to the active key. Window:
`issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 300`, the
same fixed span the chat read permit uses. The request's `org_id` /
`conversation_id` must equal the permit's, and **the owner account is taken from
the permit, never from the request** — the state directory is partitioned by
owner, so letting a caller name its own owner would let it pick whose chain it
advances.

Requests are decoded strictly through the same
`internal/keystore/handlers/strict_json.go` the display actions use: unknown
fields, duplicate JSON keys (the nested `permit` included), missing fields, and
a request over 32 KiB are refused before anything is opened. A duplicate
`conversation_id` would otherwise verify against one value and advance the
chain of another. The full order is size cap → strict decode → structural
validation → request/permit binding → window → signature, and **only then** is
the state directory opened. An unauthorized call therefore leaves no trace:
not merely a failure code, but a state directory that was never created, which
is what the handler test asserts.

**The send and receive transactions (0.0.39), and why they are not actions.**
Since 0.0.39 this package also owns two whole transactions, `Store.Send` and
`Store.Receive`, which do encrypt and decrypt. **Neither is reachable over
Native Messaging** — no action calls them, the registered action count stays 85,
and the MLS half sits behind the `mls` build tag. They are documented here
because they change what the five actions above are for: the reserve / commit
pair is the shape a chain needs when an external counter is the authority, and
once MLS is the chain it is not.

*Sending.* The order is "the record that says this position is being used
reaches the disk before the AEAD call that uses it" (design §7.2.1, T-c). The
encryption is **inside** the per-conversation lock, which the reserve path's
shape does not allow: reserving a number under the lock and encrypting after it
releases lets two processes take different numbers, load the same stored group
state, and encrypt at the same step of the ratchet — the number never decided
which key was used, the state did. So one critical section covers reading the
next position, writing the intent, encrypting, and writing the advanced state
with the ciphertext. The cost is lock occupancy across an AEAD call.

*The window that leaves.* A crash between the two writes leaves an intent with
no ciphertext behind it. Whether that position was consumed cannot be known from
the disk, so it is treated as consumed: the next send derives the key and throws
it away (`next_encryption_key`), and starts from the one after. A gap in the
chain is ordinary for MLS; handing the number out twice is the failure this
package exists to prevent. Burning is one-directional on purpose — a position
the ratchet has already passed is not burned again.

*Receiving.* Not a mirror. RFC 9420 §9.2 makes a decrypt consume the key and
requires its immediate deletion, so a success cannot be repeated: dying between
"the decrypt succeeded" and "the app has the plaintext" loses the message for
good, because the server's ciphertext is no longer openable by anyone. The
boundary is therefore atomicity rather than order. The advanced group state, the
delivery mark and a **sealed local copy** of the plaintext are one file
replacement, and a re-read is served from that copy rather than from the wire
(design §8.4 (a)). The copy is sealed under a third subkey of the owner's seal
key, is never written as plaintext, and lives inside the record because a
separate file would be a second atomicity unit. Its retention period, its
erasers beyond the ring, and whether the record is the right home are still
open (M4.6.1 / M4.6.2 / M4.6.3); the ring bound that ships is a file-size bound
and is not a retention promise.

*Generation declaration, fail-closed.* A sender puts `dragpass.chat.mls|1|a|<leaf
index>|<generation>` in the MLS `authenticated_data`, which the sender's
signature and the AEAD both cover, so a server that edits it breaks the message.
A receiver compares it against the generation the library actually derived keys
from. If the library reports **no** generation the delivery is refused rather
than read as zero: upstream reaches its `None` by folding an extraction failure
into a default, so a substituted zero would make "compared it" and "could not
look" the same answer. A missing declaration, a malformed one and a mismatch are
refused the same way, and a refusal returns an error, never an empty plaintext
and never a plaintext with a warning attached. A build assembled without
`export_key_generation` would therefore close the receive path completely, which
is asserted rather than assumed.

**The commit transactions (0.0.40), and why building one changes nothing.**
`Store.BeginCommit` and `Store.ConfirmCommit` join the two above. They are not
reachable over Native Messaging either, and the registered action count is
still 85.

RFC 9420 §14: "The generation of Commit messages MUST NOT modify a client's
state, since the client doesn't know at that time whether the changes implied by
the Commit message will conflict with another Commit or not." Two members can
build a Commit against one epoch and only one of them can have it. A device
that moved its confirmed state while building has nowhere to return to when it
turns out to be the other one. So `BeginCommit` writes the built Commit into
`Record.Pending` and leaves `Record.Epoch`, the send chain and the rollback
anchor exactly where they were; `ConfirmCommit` is the only call that moves
them, and only once the server has said which Commit its epoch took.

*Who decides.* There is no delivery service. The layer that promotes one Commit
per epoch is ariadne's compare-and-set on `expected_epoch`, and Keeper is the
half that takes the verdict. It never infers one.

*Three outcomes.* **Accepted**: the pending becomes confirmed, the epoch moves
to `expected_epoch + 1`, and the Welcome becomes releasable for the first time.
**Superseded**: the fork is dropped with the next-epoch secrets in it and the
winner's Commit is applied to the epoch this device never left — that is the
whole reason the confirmed state had to stay put. **Unresolved** is the absence
of a verdict, and it is not guessed at: the pending stays, `BeginCommit`, a new
`Send` and a new `Receive` are refused, and the caller settles it by asking the
server about `client_commit_id`, which is unique there. A retransmission and a
re-read from local history are not refused, because neither touches the ratchet
or the epoch.

*Where the fork lives.* Inside `Record.GroupState`, not beside it. mls-rs holds
a built Commit in `Group::pending_commit` and its `Snapshot` carries that field
through `write_to_storage` and back through `load_group`, so the record needs no
second serialization format and a restart finds the pending Commit where it left
it. Three things come with staying in the library's shape: a second build is
refused by the library (`MlsError::ExistingPendingCommit`) and not only by the
record, applying somebody else's Commit drops ours inside the same operation
that applies theirs, and there is no second blob to version. The cost is that
the confirmed state and the fork share one blob, which is why keeping the anchor
on the confirmed axis is code rather than layout — `Record.Epoch` never takes a
pending epoch. Written there, a lost race would read as `rec.Epoch < anchor.Epoch`
on the next load and latch a conversation for losing a race it is meant to lose
sometimes.

*What a pending Commit costs on disk.* A `PendingCommit` carries the next
epoch's state, epoch secrets and key schedule, so while one is outstanding the
file holds two epochs' worth of secrets. Measured on a two-member group:
**1505 bytes confirmed, 3770 with a pending Commit (+2265), 1890 once it is
settled** (the settled figure is above the first because applying a Commit
inserts the prior epoch). That is the concrete form of RFC 9420 §14's other
requirement, that a forked state be deleted as soon as it is not needed, and the
reason the three outcomes have to be reached quickly.

*No handshake ratchet is involved.* `encrypt_control_messages` is pinned false,
so a Commit goes out as a `PublicMessage` and derives nothing from the handshake
ratchet; it does not touch the application ratchet either. Design §7.3.4 says a
losing Commit's handshake generation is not reclaimed — under this setting there
is no generation to reclaim, which is asserted by comparing the send position
before and after a build. The rule is true on an empty set rather than removed:
flipping the setting brings the axis and the rule back together.

**Ordering rules that are not tunable.** `chat_state_reserve_send` persists and
fsyncs the consumption of the positions *before* it answers, so a crash between
the answer and the encryption loses a message and never reuses a position; a gap
in the chain is ordinary, a repeat is not recoverable. `chat_state_mark_received`
persists before it answers for the mirror reason: a redelivery must advance the
state once, not twice. `fsync` cost can be traded away with block reservation
(`count` up to 64), but the order itself cannot.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`chat_state_reserve_send`|`permit`: `{ account_id, org_id, conversation_id, watermark_epoch, watermark_leaf_index, watermark_next_handshake, watermark_next_application, issued_at, expires_at, server_key_version, signature }`, `org_id`, `conversation_id`, `count` (1..64)|`{ epoch, first_chain_index, count, generation }`|Consumes `count` chain positions for sending and returns them. The consumption is on disk and fsynced before the response leaves — that is the whole point of the action, and the reverse order would let the next send encrypt a different plaintext under the same `(key, nonce)`. Positions `[first_chain_index, first_chain_index + count)` are spent and are never handed out again, across a crash included. Refused whole with `CHAT_STATE_REKEY_REQUIRED` if either rollback axis says the state has been rewound.|
|`chat_state_commit_outbox`|`permit`, `org_id`, `conversation_id`, `client_message_id`, `epoch`, `chain_index`, `iv_b64` (12B), `ciphertext_b64` (ciphertext ‖ tag, 17..8208B)|`{ stored, epoch, chain_index, iv_b64, ciphertext_b64 }`|Stores the ciphertext built for a position this conversation already reserved, so a retransmission is a retransmission. **Idempotent on `client_message_id`**: a second call writes nothing and returns what is already stored, so a lost response cannot become a second encryption at a second position — which is why `stored: false` means the other fields are what was already there, not what the request carried. A position that was never reserved, or one that already carries a different message, is refused with `CHAT_STATE_CONFLICT`. The outbox is a 64-entry ring; an entry that has fallen off answers a later retransmission with `CHAT_STATE_NOT_FOUND` and the position is abandoned rather than re-encrypted.|
|`chat_state_read_outbox`|`permit`, `org_id`, `conversation_id`, `client_message_id`|`{ epoch, chain_index, iv_b64, ciphertext_b64 }`|Returns the bytes a retransmission must send. Everything it returns is public material the transport already carries; the permit is required because the set of conversations this device holds state for is not.|
|`chat_state_mark_received`|`permit`, `org_id`, `conversation_id`, `epoch`, `sender_leaf_index`, `content_type` (`"handshake"` \| `"application"`), `generation`|`{ first_delivery, generation }`|Records an inbound position and reports whether this delivery was the first. Persisted before the answer, so a redelivery advances the state once and a key forward secrecy says is gone does not come back because a crash replayed its deletion. **Four slots name the position, not two.** MLS gives every sender its own sender ratchet (RFC 9420 §9.1) and gives each sender a handshake one and an application one (§6.3.1), so `(epoch, generation)` is not unique in a group: two members' first message of one epoch would each be judged a redelivery of the other and one of them would be dropped. The fifth slot of the identifier is the conversation, which is the record itself. An unknown `content_type`, or the earlier two-slot request shape, is refused with `CHAT_STATE_INVALID_INPUT` before the state directory is opened. Mind the one name that means two things across this action: the request's `generation` is the step along the named ratchet, the response's is the record's own write counter. The received ring holds 1024 positions.|
|`chat_state_purge`|`owner_account_id`|`{ removed_conversations }`|Erases one account's chat state: the sealed files, the anchors, and the seal key. Logout calls it, because a logout knows whose state is going away; a device reset does not name an account, so `reset_device_identity` erases every owner's state in-process rather than through this action. Unlike `peer_key_pin`, which survives a logout so a human's out-of-band check is not thrown away, chat state must not — what is left behind is an entrance for a rewound chain later. The seal key goes **last**, and its removal is what makes the erasure final: a state file restored from a backup afterwards cannot be opened under the key that replaces it, so a purge cannot be used to clear a latched rekey requirement and then bring the rewound file back. **The one action here with no permit**: it only deletes, any local process can already delete these files with the filesystem, and requiring a server round trip would make erasure fail exactly when the user is logging out of a server they cannot reach.|

**No new plaintext carve-out.** Nothing in this group returns plaintext:
`ciphertext_b64` and `iv_b64` are the bytes that go on the wire, and `epoch` /
`chain_index` / `generation` / `sender_leaf_index` / `content_type` /
`client_message_id` / `first_delivery` / `stored` are metadata. `TestNoRawSecretInResponseTypes` and
`TestNoRawSecretInRequestTypes` both pass unchanged. The serialized group state
is never carried in either direction: it is opaque bytes inside the sealed file
that only in-process Keeper code touches, and no action reads or writes it.

Domain error codes for these five are more specific than the coarse taxonomy
below and travel in the same `error_code` field. They are shared verbatim with
the server and the Extension:

|Code|Trigger|
|---|---|
|`CHAT_STATE_INVALID_INPUT`|Malformed syntax, wrong size, an unknown / duplicate / missing field, a request over 32 KiB, or a `count` outside 1..64.|
|`CHAT_STATE_NOT_AUTHORIZED`|Permit signature, request/permit binding, or window failure. Deliberately one code for all three — which check refused is not something an unauthorized caller gets to learn. Nothing was read or written, and the state directory was not opened.|
|`CHAT_STATE_LOCK_TIMEOUT`|Another process held the conversation lock past the ceiling. Its own code so the caller never has to infer from a generic failure whether proceeding without the lock is an option. It is not: retry, or surface the failure.|
|`CHAT_STATE_CONFLICT`|The state changed between the read and the write inside one locked section, or the named position was never reserved or already carries a different message. In every case the write did not happen. A conflict under a held lock means the lock stopped working, so it surfaces as a failure rather than as an overwrite.|
|`CHAT_STATE_REKEY_REQUIRED`|The stored state is behind the anchor or behind the server's watermark. Sending is locked for this conversation until a new epoch is established. **No retry path and no bypass** — the latch is the feature. Establishing the epoch belongs to the MLS layer, which is not here yet; `chat_state_purge` is the only other way out.|
|`CHAT_STATE_NOT_FOUND`|No outbox entry for that `client_message_id`. A retransmission this late is abandoned, never re-encrypted.|
|`CHAT_STATE_STORAGE_FAILURE`|The state directory or the keyring could not be read or written. Nothing was committed.|

### Peer account key pins (account key trust v1)

Every Group DEK the Extension wraps to a member is wrapped to a public key the
**server** chose (`GET /orgs/:id/members` → `public_key`). Nothing used to
check that the server kept choosing the same one. A pin is that check: one
keyring entry per (owner account, peer account) holding the fingerprint the
owner already accepted and how much trust it carries.

The check lives in the Keeper rather than in the server API or the Extension,
because what it defends against is a malicious server, not a malicious
Extension. An Extension already under an attacker's control has easier routes
than omitting an account id. A server, on the other hand, can swap a key while
the Extension behaves perfectly, and the only place that swapped key is
actually *used* is the Keeper's wrap. Putting the check there means "wrap to
the key the server gave me" cannot happen without passing it.

**Fingerprint.** `hex(sha256(pem bytes))`, over the PEM exactly as received.
Nothing is trimmed or re-encoded first: the Extension, the server, and the
Keeper hash the same bytes, and one added newline would split the three results
without anything failing loudly. This is deliberately *not* the
`account_device_keys` formula, which hashes the Base64 string; that one stays an
internal identifier. `docs/testing/fixtures/account-key-trust-v1.json` pins both
values so an implementation that reaches for the wrong one is caught.

**States.** `tofu` (first observation, nobody checked it), `verified` (a human
compared it out of band), `rotated` (a signed chain moved the pin forward),
`changed` (the key differs and nothing explains it). `changed` is never stored:
it is a verdict, and the pin it was measured against is left exactly as it was.

**The rotation statement** is how a key change explains itself to everyone who
pinned the old key. Canonical, seven items, no newlines:

```text
dragpass.keyrotation|1|<account_id>|<old_fingerprint>|<new_fingerprint>|<rotated_at_unix>|<reason>
```

Both signatures are RSA-PSS SHA-256 over the identical bytes: `old_signature`
by the key being left, `new_signature` by the key being taken up. `reason` is
`voluntary`, `recovery`, or `compromise`. The domain prefix puts it in the
`dragpass.` family alongside `dragpass.chat`, `dragpass.chat.read`, and
`dragpass.message`, so a statement signature verifies nowhere else.

**What the wrap path does** with (pin, observed fingerprint, claimed chain):

1. No pin → `tofu`, allow, remember it.
2. Pin matches → keep the state, allow, touch `last_seen_at`.
3. Pin differs → verify the chain. It has to start at the pinned fingerprint,
   end at the observed one, link end to end, name this account in every
   statement, carry fingerprints that its own public keys actually hash to, and
   have both signatures verify. Then the pin advances to `rotated` and
   `verified_at` is dropped: a human checked the previous key, not this one.
4. Anything else → `peer_key_changed`. No wrap output, no pin mutation, no
   retry that launders it. Only `peer_key_pin_verify` moves a pin across a
   change the chain does not explain.

`compromise` anywhere in a chain forces `changed`, because the holder is saying
the old key is in someone else's hands and the earlier links may be the
attacker's. `recovery` is an ordinary operational event and succeeds exactly
like `voluntary`.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`peer_key_pin_list`|`owner_account_id`|`{ pins: [{ account_id, fingerprint, state, first_seen_at, last_seen_at, verified_at? }] }`|Every pin this owner holds on this device, in index order. No pins is an empty list, not an error. Only the count is logged.|
|`peer_key_pin_get`|`owner_account_id`, `account_id`|`{ found, pin? }`|One pin. Absence is data rather than `not_found` — the caller uses it to decide whether fetching a rotation chain is worth it at all, since a first observation is trust-on-first-use and a chain would prove nothing.|
|`peer_key_pin_verify`|`owner_account_id`, `account_id`, `fingerprint` (hex 64), `public_key` (PEM)|`{ state: "verified", fingerprint }`|Settle a fingerprint a human compared out of band. The Keeper recomputes the fingerprint from the PEM and refuses with `crypto_failure` if it differs, leaving the pin untouched: if the user checked A while the server is serving B, promoting B would launder exactly the substitution the model exists to catch. Works on a peer with no pin yet.|
|`peer_key_pin_forget`|`owner_account_id`, `account_id`|`{ forgotten }`|Discard a pin. The only path that removes one — account reset and logout leave pins alone, so a human's verification survives signing back in on the same device. Idempotent (`forgotten:false` when there was none) and still prunes a stale index entry.|

All four take lowercase hyphenated UUIDs and reject the nil UUID. `fingerprint`
must be 64 lowercase hex characters; uppercase is rejected rather than folded,
since two spellings of one fingerprint would compare unequal somewhere
downstream.

**Storage.** `peer-pin:<owner>:<peer>` holds the record (~230 bytes);
`peer-pin-index:<owner>:<n>` holds up to 48 peer ids per chunk, because
`SecretStore` has no listing operation and the Windows Credential Manager caps
an entry at roughly 2.5 KB. Chunk numbers are assigned once and never reused or
renumbered: enumeration walks upward from 0 and stops at the first missing
number, so renumbering would silently truncate the set. A delete empties its
slot in place.

**The owner id is scoping, not authorization.** It exists so two accounts
sharing a machine keep separate trust records. A caller naming someone else's
id reaches that owner's pins only if they are already on this device under this
OS user, and what it would learn is a list of fingerprints.

**Owner trust-on-first-use (0.0.33).** The owner half of that name arrives as a
request field whose original source is the server (`GET /account/me` → account
id). Until 0.0.33 nothing checked it, and that was one lie short of a bypass:
swap a member's public key *and* report a different account id, and the Keeper
reads a namespace nothing was ever written to. Every peer is a first
observation, TOFU allows the wrap, and the fingerprints a human verified sit in
the old namespace where nothing consults them — `changed` never fires. The same
lie empties `peer_key_pin_list`, so the SPA's blocked banner loses the rows it
would have drawn.

So the Keeper records the first owner id it is ever given, in a single
`peer-key-owner` entry under `config.Service` alongside `peer-key-policy`, and
refuses every request carrying a different one with `peer_key_owner_mismatch`.
The check runs before anything else in each handler, so a mismatch reads no
pin, writes no pin, and produces no wrap output. Recording on first use is not
a pin mutation and happens even when the call goes on to be refused for another
reason.

|Takes an owner id, so it is checked|Does not, so it is not|
|---|---|
|`dek_rewrap_for_member`, `dek_unwrap_and_rewrap_for_many` (when `owner_account_id` is present — a pre-0.0.31 call has no namespace to be steered into), the four `peer_key_pin_*` actions, `peer_key_chain_evaluate`|`peer_key_policy_get` / `peer_key_policy_set` (the policy is a device setting), `peer_key_owner_reset`|

**Be exact about what this buys.** It stops a server that *switches* the id
later, which is the attack above, because the pins worth bypassing were written
under the first id. It does **not** stop a server that lies consistently from
the very first use: that server picks the namespace, and the Keeper has no
independent source for an account id to check a first claim against — the id is
a server-side concept and nothing in the Keychain derives it. That residual
case is harmless, though, because the namespace is only a label. The pins
written inside it are real pins over real peer fingerprints, so substituting a
peer key later still lands on `changed`.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`peer_key_owner_reset`|none|`{ reset }`|Forget which account this device's pins belong to, so the next request binds a new one. Idempotent (`reset:false` when there was nothing recorded). Pins are left where they are, so signing back in as a previous owner finds the verifications already made. The cleared id is deliberately not echoed.|

**`peer_key_owner_reset` must be reachable only from the extension options
surface.** No SPA route, no content script, no path a server response can
steer: a caller who can clear the record can then pick the namespace the owner
check exists to fix. **The Keeper cannot enforce this itself.** Four surfaces
spawn the same binary over the same stdio loop and it does not know which one
is on the other end (`dragpass-control-plane`
`docs/security/adr-ratchet-state-storage.md` §3.1), so this is a client-side
obligation stated here rather than a check made in Go. A client must also never
call it automatically on `peer_key_owner_mismatch` — that code is exactly the
signal the reset would erase.

**The `peer_key_changed` refusal carries data.** It is the only failure
response in the protocol that does, because the caller's next move is to put
the two fingerprints in front of a human and ask which one is right:

```json
{ "success": false, "error_code": "peer_key_changed",
  "data": { "observed_fingerprint": "<hex 64>", "pinned_fingerprint": "<hex 64>" } }
```

`observed_fingerprint` is the key the server is serving now; `pinned_fingerprint`
is the one this owner had already accepted, and it stays the stored value
until `peer_key_pin_verify` settles the difference. Both are hashes of public
keys, so the payload adds nothing the refusal did not already imply, and it
saves the SPA from re-fetching the very key the refusal is about.

**Accepted gap.** A recipient with no account id — the org archive key, which
is an org resource rather than an account — is exempt. A server that swaps the
archive public key can still receive an OLD Group DEK. Archive key pinning is
out of scope for this slice.

**Evaluating without wrapping (0.0.33).** The pin only advanced to `rotated`
inside a wrap, and the SPA blocks all four wrap entry points — invite, DEK
rotation, retained backfill, DM open — while the pinned fingerprint differs
from the key the server is serving. A peer who rotated legitimately therefore
locked the org: the signed chain that explains the change existed, and no call
could put it in front of the Keeper. The banner's two exits were both wrong.
Out-of-band verify asks a human to redo work a signature already did, lands on
`verified` rather than `rotated`, and drops `last_rotation_fingerprint`, so the
"this key changed" signal disappears — and the same button launders a genuine
substitution just as readily. Forget deletes the pin so the next wrap is TOFU,
which is discarding the protection.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`peer_key_chain_evaluate`|`owner_account_id`, `account_id`, `public_key` (PEM the server is serving now), `rotation_statements?`|`{ state, fingerprint, advanced, pinned_fingerprint? }`|Run the trust state machine for one peer and report the verdict, wrapping nothing. `state` is one of the four; `fingerprint` is what the Keeper computed from the PEM, never a value the caller sent; `advanced` reports whether the stored pin moved. Same caps as the wrap actions: 32 statements, 512 KiB per request, checked before the decode.|

It runs **the same** state machine the wrap path runs, on the same inputs, and
persists the pin the same way: a valid chain advances the pin to `rotated`,
clears `verified_at`, and sets `last_rotation_fingerprint`; a refusal reports
`changed` with both fingerprints and changes nothing. There is no second copy
of the logic, which is the point — the wrap's answer and this answer have to be
the same answer.

The verdict rides the **success** envelope even when `state` is `changed`,
unlike the wrap refusal. The action succeeded at what it was asked to do, and
`changed` is a verdict rather than a failed evaluation. Nothing is lost by
that: the wrap is still the enforcement point, so a caller that ignores `state`
and wraps anyway is refused there with `peer_key_changed` exactly as before.

`advanced` is false when the observed key was already the pinned one (only
`last_seen_at` moved) and false on every refusal. A peer with no pin yet is
recorded as `tofu` with `advanced:true`, the same as a first wrap would.

**It does not widen what a local caller can do.** Anyone who can reach the
Keeper's stdio loop can already call `dek_rewrap_for_member` with these same
fields, and that action runs this same evaluation before it produces anything.
What this removes is the need to hold a wrapped Group DEK in order to ask the
question, not a check.

**Strict mode (0.0.32).** A device-local policy, off by default, that narrows
the wrap path to keys a human has actually compared.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`peer_key_policy_get`|none|`{ require_verified_peers }`|The device policy. A device that never set one reads the default, which is off.|
|`peer_key_policy_set`|`require_verified_peers`|`{ require_verified_peers }`|Turn strict mode on or off and report what is now stored. The field is required: a payload that omits it is `validation_error` rather than a silent switch-off, since that is the one direction this action must not move by accident.|

With it on, a wrap to any peer whose pin is not `verified` is refused with
`peer_key_unverified`, produces no wrap output, and leaves the pin exactly as
it was. That covers all three of the allowed outcomes: a first observation with
no pin yet, an existing `tofu` pin nobody got around to checking, and a
`rotated` pin whose chain verified but whose current key no human has read
aloud. The first observation is the one it would be worst to let through, since
that is the wrap that actually hands the Group DEK to a key nobody looked at.
The batch action refuses whole, the same way it does for `changed`.

`changed` is unaffected. It is the state machine's verdict rather than the
policy's, so it keeps `peer_key_changed` and its two fingerprints with the
toggle in either position, and strict mode never renames a detected
substitution into a milder-sounding policy refusal. A call that names no
account id has no pin to judge and is not affected either — the pre-0.0.31
shape behaves as it always did.

**Strict mode does not narrow `peer_key_chain_evaluate`.** Its rule is "do not
wrap to a key nobody compared out of band", and that action wraps nothing, so
it has no output to withhold; it reports the true state instead of
`peer_key_unverified`. Refusing there would make the deadlock the action exists
to break strictly worse — a strict device could never learn that a rotation
chain was valid, and would be left with the two wrong exits above. The
enforcement point does not move: a pin the evaluation carried to `rotated`
still refuses the next wrap with `peer_key_unverified` until a human verifies
it, so reporting the true state hands out no wrap strict mode would have
refused. It only lets the UI ask for that verification against the right key.
One consequence worth stating plainly: on a strict device the evaluation does
persist a pin the wrap would not have, because a policy refusal short-circuits
before the wrap path's write. The record that lands is the same one the state
machine decided either way, and it buys no wrap.

**The policy is per device, not per owner.** One entry, `peer-key-policy`,
under `config.Service` with no owner in the name. Pins answer "is this the key
I accepted for this peer" and are owner-scoped; the policy answers "how much do
I insist on before wrapping at all", and a machine that requires out-of-band
checks requires them for whoever is signed in. It is read once per enforced
call, so a rotation cannot judge half its members under one answer and half
under another. The server has no path to the value in either direction: nothing
on the account backs it and no action reads it on the server's behalf. The
extension options page is the only caller.

### Personal DEK (Phase 12d)

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`dek_generate_and_wrap_dual`|`password`|`{ password_wrapped_dek_b64, device_wrapped_dek_b64 }`|Dual wrap (password + deviceKey). Signup. Server form Base64(salt(16)‖iv(12)‖ct); local form Base64(iv(12)‖ct). deviceKey is fetched from Keychain inside Keeper (Keeper 0.0.8 fix-forward — never crosses IPC).|
|`dek_rotate_to_device_key`|`password`, `encrypted_dek_b64`|`{ device_wrapped_dek_b64 }`|Login: re-wrap server password-wrap with deviceKey. deviceKey from Keychain.|
|`dek_unwrap_and_encrypt`|`encrypted_dek_b64`, `plaintext_b64`|`{ iv_b64, ciphertext_b64 }`|Personal scope encrypt. deviceKey from Keychain.|
|`dek_unwrap_and_decrypt_meta`|`encrypted_dek_b64`, `meta_fields` (key→Base64(IV‖ct))|`{ fields }` (key→plaintext UTF-8)|Bulk decrypt of personal entry meta fields. plaintext metadata carve-out — value plaintext echoed 0 times.|

The retired Group Item DEK actions are not part of the current protocol. Group
DragLink tokens use the direct Group DEK actions above. Personal entries use
the Personal DEK actions below.

### Decrypt-to-clipboard (Keeper-owned plaintext sink)

Keeper owns the plaintext sink: it decrypts in process memory and writes the plaintext directly to the OS clipboard via `Deps.Clipboard`. Responses carry no plaintext / `plaintext_b64` / preview / length metadata. `clipboard_ttl_ms` must be in `[5000, 60000]`.

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`dek_unwrap_and_decrypt_to_clipboard`|`encrypted_dek_b64`, `iv_b64` (12B), `ciphertext_b64`, `clipboard_ttl_ms`|`{ copied, clipboard_ttl_ms }`|Personal decrypt → Keeper clipboard. deviceKey from Keychain. No plaintext echoed.|
|`group_decrypt_to_clipboard`|`group_handle`, `iv_b64` (12B), `ciphertext_b64`, `clipboard_ttl_ms`|`{ copied, clipboard_ttl_ms }`|Drag/audit token → Keeper clipboard. No plaintext echoed.|

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
|`peer_key_changed`|A wrap named a peer whose public key no longer matches the pinned fingerprint and no valid rotation chain explains it. Nothing was wrapped; the pin was left as it was. **Carries `data: { observed_fingerprint, pinned_fingerprint }`** — the only failure response that does.|Stop the whole flow (invite / rotation / backfill / DM), never just the one member, and show both fingerprints from the payload for a human to compare. No retry and no bypass: the user either confirms through `peer_key_pin_verify` or forgets the peer.|
|`peer_key_unverified`|Strict mode is on (`peer_key_policy_set`) and the peer's pin is not `verified` — a first observation, a `tofu` pin, or a `rotated` one. A policy refusal rather than a detected substitution, so it carries no `data`: there are no two fingerprints to weigh up, only one nobody has checked. Nothing was wrapped and the pin was left as it was.|Stop the flow and point the user at the out-of-band check for that member (`peer_key_pin_verify`), or at turning the policy off. In use from 0.0.32; in the enum since 0.0.31 so both sides could be written against one spelling.|
|`peer_key_owner_mismatch`|The request carried an `owner_account_id` that is not the one this device recorded the first time it was given one (0.0.33). The owner half of a pin's keyring name originally comes from the server, so a server that reports a different account id would push every lookup into an empty namespace where every peer reads as a first observation and TOFU waves the wrap through. Nothing was wrapped, no pin was read or written, and no pin list was returned. Carries no `data`: neither id goes back, since the recorded one is what a caller probing for the namespace would want.|Stop the flow. This is either a server reporting the wrong account or a device genuinely changing hands; the only way forward is `peer_key_owner_reset` from the extension options page, which the user has to choose deliberately. Never call it automatically in response to this code.|

The `error` string is sanitized but **may include field names** (e.g.
`wrap_key_b64: must be 32 bytes`). It never includes secret values. Mapping
between Go sentinel errors and codes lives in `internal/keystore/errs/errs.go`
(`CodeForError`):

- `*ValidationError` → `validation_error`
- `ErrSecretNotFound` / `ErrServerKeyVersionNotFound` / `ErrNoActiveServerKey` /
  `ErrRecoverySessionNotFound` / `ErrGroupSessionNotFound` → `not_found`
- `ErrRecoverySessionExpired` / `ErrGroupSessionExpired` → `expired_session`
- All other errors → `internal_error`

`crypto_failure`, `storage_failure`, `unsupported`, and the three
`peer_key_*` codes are not auto-mapped — the handler that detects the failure
assigns them explicitly via `errorCodeResponse(...)`.

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
|0.0.7|`archive_key_split`, `archive_share_rewrap`, `archive_session_begin`/`_end`, `archive_quorum_combine_and_rewrap`, `account_archive_key_generate`/`_status`|Archive-key admin quorum (Shamir N-of-M break-glass). Splits the org archive private key across M admin devices (in-repo GF(2^8) Shamir, hybrid RSA-OAEP+AES-GCM share wrap) and deletes the whole key; break-glass reconstructs it only inside the coordinator's Keeper during an N-approval recovery session, wiping all key material before returning only the re-granted wraps. Also introduces the per-account archive receiving keypair in its own slot (published to the server account directory; receives handoff grants and quorum shares; survives the org-slot wipe) and gives `archive_unwrap_and_rewrap` an account-slot decrypt fallback for handoff-received grants.|
|0.0.8|`archive_key_rotate_begin`/`_commit`/`_abort`|Same-device org archive key rotation via a staging slot. `archive_key_generate` is idempotent, so re-running it on the same device is a no-op — real rotation needs the OLD key to stay live while grants are re-wrapped. `begin` stages a NEW keypair (active slot untouched, so `archive_unwrap_and_rewrap` still unwraps with the OLD key until commit), `commit` promotes staging → active (wiping the old active private key at rest), `abort` discards staging. Best-effort from the Extension's side — an older Keeper returns `unsupported`.|
|0.0.9|Remove `aes_generate_and_wrap`|Vault-deprecation leftover: the action returned a raw Item DEK (`item_dek_raw_b64`) over IPC and had no live extension consumer. Raw Item DEK must not cross the IPC boundary. Adds a registry-wide regression guard (`proto.TestNoRawSecretInResponseTypes`) that fails CI if any action's response type carries a raw-secret field without an explicit carve-out; at introduction the only carve-out was `unwrapgroupdek` (`group_dek_b64`, client-side Group DEK cache), removed in 0.0.11.|
|0.0.10|`group_encrypt`, `group_encrypt_meta`, `group_decrypt_meta`|Encrypt-direction mirror of `group_decrypt_to_clipboard`: `group_encrypt` AES-GCM seals plaintext directly under the raw Group DEK behind the opaque handle (no Item DEK indirection), returning `{ iv_b64, ciphertext_b64 }`. First step of moving drag encryption off client-side AES-GCM onto Keeper handles. The metadata path adds `group_encrypt_meta` / `group_decrypt_meta`: the same batch meta-field contract as `aes_unwrap_and_decrypt_meta` with the Item DEK unwrap step replaced by a direct raw Group DEK use — the encrypt output feeds straight into decrypt, in the combined Base64(IV‖ct) form the Extension stores per meta field. Metadata decrypt keeps the plaintext-metadata carve-out (value plaintext never returned). Also removes the stale `aes_rewrap` row from the Item DEK catalog table: that action was dropped together with the `item_dek_grants` schema before the public version epoch (no `HandleAESRewrap`, not registered), and only the catalog row lingered.|
|0.0.11|Remove `unwrapgroupdek` / `group_session_open_with_raw`|Raw Group DEK no longer crosses IPC in either direction; all group crypto is handle-based. `unwrapgroupdek` (RSA-OAEP unwrap returning the raw 32B Group DEK) and `group_session_open_with_raw` (register a raw 32B Group DEK directly) are removed from dispatcher / proto / handler. `group_session_open` (unwrap into a Keeper-held opaque handle) is the only Group DEK open path. Removes the last `TestNoRawSecretInResponseTypes` carve-out (`UnwrapGroupDEKResponseData.group_dek_b64`) — the carve-out list is now empty.|
|0.0.12|Remove `wrapgroupdek` — dead capability; raw Group DEK cannot exist in extension JS, so a raw-input wrap action has no legitimate caller|`wrapgroupdek` RSA-OAEP-wrapped a raw 32B Group DEK supplied in the request. With a raw Group DEK unable to exist in the extension JS heap, this input path had zero live consumers; member grant / rotation wraps are synthesized inside the Keeper (`group_dek_generate_and_open` / `dek_rewrap_for_member` / `dek_unwrap_and_rewrap_for_many`). Removed from dispatcher / proto / handler. Adds the request-direction guard `proto.TestNoRawSecretInRequestTypes` (mirror of `TestNoRawSecretInResponseTypes`): no `*Request` may accept raw key material as input, the only carve-out being encrypt-direction `plaintext_b64`.|
|0.0.13|`group_encrypt_with_aad`, `credential_http_request`|AAD-binding variant of `group_encrypt` for the MCP Credential Control Plane. AES-GCM-seals plaintext under the raw Group DEK behind the opaque handle while binding a required caller-supplied AAD (canonical `org_id\|entry_id\|payload_kind\|schema_version\|dek_version`) into the GCM tag, so a sealed credential payload cannot be swapped to a different context without failing to open. Adds sibling crypto `AESGCMSealSplitWithAAD` / `AESGCMOpenWithAAD` (the AAD=nil `group_encrypt` path is unchanged). `plaintext_b64` carved out in `TestNoRawSecretInRequestTypes` like the other encrypt-direction actions; `aad_b64` is public context material. The same release adds `credential_http_request` (PR-K2), the Keeper's first network surface and its own action / registry fragment: a decrypt-to-tool HTTP sink that opens the AAD-bound sealed credential (`AESGCMOpenWithAAD`), injects it into a `{{secret.<key>}}` header template, and performs one guarded outbound request behind eight safeguards — policy host/method re-validation, connect-time SSRF / private-IP blocking (`Dialer.Control` re-checks the resolved IP), HTTPS-only with TLS verification on, all redirects blocked, response size cap + truncation, request timeout, response redaction (`Authorization` / `Set-Cookie` / `Proxy-Authorization` stripped, secret masked if echoed), and payload zeroize after use. No new dependency — `net/http` is stdlib. The plaintext credential never crosses IPC (request, response, or logs); its request fields (`iv_b64` / `ciphertext_b64` / `aad_b64` / `header_template` placeholders) carry no raw secret, so `TestNoRawSecretInRequestTypes` / `TestNoRawSecretInResponseTypes` pass with no new carve-out. Server-signed policy verification (design §5) landed in 0.0.14, not here.|
|0.0.14|`credential_http_request` verifies the server-signed policy|Activates server-signed policy verification (`verifyCredentialPolicy` in `internal/keystore/handlers/credential_policy.go`, called from `credential_http.go` before the request is built): RSA-PSS over the canonical policy, expiry, and the AAD binding (entry id, payload kind, schema version, dek_version) must all hold, and the signed target host / path / method must match the request, or the action fails without sending anything. The same release enforces the signed request shape and redacts encoded and escaped secret echoes in response bodies in addition to literal echoes.|
|0.0.16|No protocol change|Release packaging enables CGO for the macOS Cocoa user-presence backend.|
|0.0.17|`auth_signup_prepare`, `auth_recovery_begin`, `auth_recovery_prepare`, `auth_recovery_reissue_prepare`|Moves signup and recovery KDF, keypair, wrapping, and recovery-key reissue operations into Keeper. Password and RK24 inputs are request-only, and responses return only encrypted or public material.|
|0.0.25|`dek_unwrap_and_encrypt_with_aad`, `credential_http_request` (personal key source)|Extends the Credential Control Plane to personal scope. `dek_unwrap_and_encrypt_with_aad` is the personal-scope sibling of `group_encrypt_with_aad`: it unwraps the device-wrapped personal DEK and seals under it while binding the same canonical AAD shape (`account_id` replaces `org_id`), so a personal sealed credential payload carries the identical swap guard. `credential_http_request` takes either a `group_handle` or an `encrypted_dek_b64`, exactly one. Only the key source branches (`withCredentialDEK`); all safeguards stay in one implementation.|
|0.0.26|`credential_http_request` local personal key source|Persists the validated device-wrapped personal DEK in the Keeper Keychain during signup, login, rotation, and personal credential sealing. `credential_http_request` adds `use_local_personal_dek=true` as an exclusive key source, allowing MCP to execute personal credentials without receiving DEK material. Device identity reset deletes the new slot.|
|0.0.28|`credential_exec_request`|Adds the second decrypt-to-tool sink: the credential is placed in the environment of one local child process instead of an outbound HTTPS request. Everything the two sinks share runs the same code (`withCredentialDEK`, the AAD binding, `verifyCredentialPolicy`, `resolveSecretPlaceholders`, `maskSecrets`); only the destination is new. What changes structurally is what the signature binds. An HTTP policy pins a network target and `allowed_hosts` exact-match keeps the credential from going elsewhere; exec has no counterpart, because a child that has read the environment can open any socket it likes. So the policy carries the command instead — `exec_executable`, `exec_argv` (argv[0] is the executable), `exec_cwd`, `env_template` — and the canonical policy string appends that block **only when `env_template` is non-empty**, after the equally conditional `query_template` slot. A policy injects into exactly one place, so the two blocks are never both present, and every header / cookie / query policy signs the exact bytes it did in 0.0.27: an older Keeper keeps verifying a newer server's HTTP policies, and there is no lockstep window this time. Every part of that block is length-prefixed as `<byte length>:<value>`: `argv` joins its elements with `,`, and `exec_executable` / `exec_cwd` carry the same prefix on their own — a POSIX path may legally contain a pipe, and without the prefix a crafted path could absorb the following separator and make two distinct commands canonicalize to the same bytes. So the exec block reads `|<len>:<executable>|<argv canonical>|<len>:<cwd>|<env canonical>`. ariadne's `credential/sign.go` carries the byte-identical functions and both repos assert the same literal for a shared fixture. Safeguards, against the HTTP sink's numbering: (1) executable / argv / cwd / env_template must equal the verified policy or no process starts — checked in `Validate` before the payload is opened and again in the handler after the signature verifies; (2) SSRF blocking has **no counterpart** and that is recorded, not mitigated; (3) no shell — the `exec.Cmd` is built with `Path` set to the absolute executable so os/exec performs no PATH lookup, and no request field is ever parsed as a shell string; (4) `Setpgid` plus a process-group SIGKILL on timeout, so a grandchild the child left sleeping dies with it; (5) 1 MiB per stream with `truncated`; (6) a 60s Keeper-owned timeout the caller cannot widen (the policy signature does not cover resource limits); (7) `maskSecrets` over stdout and stderr; (8) the decrypted payload zeroized, the assembled environment strings dropped by reference (Go strings, the same limit as `wipeSecretStrings`); (9) the child's environment is built from a fixed allowlist rather than inherited, so the caller's `DRAGPASS_API_TOKEN` cannot reach it. The secret goes to the environment and never to argv, deliberately: `/proc/<pid>/cmdline` is world-readable and `/proc/<pid>/environ` is not — argv injection is excluded from the design, not deferred. `exit_code` is data: a command that exits non-zero returns a successful response carrying that code, the way an HTTP 401 does; only a timeout is special, reporting `timed_out` with `exit_code` -1. **Stable refusal contract:** every "the request is not the command the server signed" refusal returns `error_code` `validation_error` with a message ending in `does not match signed credential policy` — `executable: …`, `args: …`, `cwd: …`, `env_template: …` from `Validate`, and `request command does not match signed credential policy` / `env_template does not match signed credential policy` from the handler after the signature verifies. That pair (code + suffix) is what a caller keys on to report `exec_denied` rather than a generic request failure, exactly as `credential_http_request`'s `request target does not match signed execution target` is classified today; it is part of the action's contract and is not reworded without updating the callers that match it. None of the new field names match a raw-secret pattern, so the no-raw-secret guards pass with no new carve-out. **Known limitations:** nothing constrains where the child goes once it has read the environment — command-level `always_ask` approval is the entire mitigation, so a credential that must stay bound to one host should not be moved to `env`. Any process of the same uid can read the child's environment (`/proc/<pid>/environ`, `ps -E`), a grandchild that calls `setsid` escapes the process-group kill, the child's core dump is not controlled (a parent `Setrlimit` would bind the Keeper itself), and output redaction is best-effort against accidental echo rather than a defence against a hostile child. Unsupported on Windows: killing a process tree there needs a Job Object assigned before the child starts, and a timeout that kills only the direct child would leave a grandchild holding the credential — the action fails with `unsupported` rather than pretending to have a safeguard it does not.|
|0.0.29|`message_display_prepare`, `group_decrypt_with_aad_for_app_display`|Secure Message Overlay display path, and the first `TestNoRawSecretInResponseTypes` carve-out since 0.0.11. `group_decrypt_with_aad_for_app_display` returns `plaintext_b64` — the protocol's only plaintext-returning response, approved for exactly that one response type in dragpass-control-plane `docs/security/secure-message-overlay-proposed-boundary.md`; `TestNoRawSecretInRequestTypes` is unchanged and every clipboard action still returns no plaintext. Four things keep the exception from widening into "the app can decrypt anything the org can". **(1) The AAD is Keeper-built.** Neither request carries `aad_b64`, a domain, or a canonical string; Keeper assembles `dragpass.message\|1\|<org_id>\|<group_id>\|<dek_version>\|<token_expires_at>` from fields it validated, so a drag token (no AAD) and a credential payload (credential canonical) fail the GCM tag here even with the right handle and the right named context. **(2) A server signature, not an action name.** The dispatcher does not distinguish app from MCP per action, so a new action name is not an authentication mechanism. `group_decrypt_with_aad_for_app_display` requires an RSA-PSS SHA-256 permit over the 14-item canonical above, verified under the pinned key of the named version; a missing version fails closed, and an MCP service token cannot obtain such a permit. Every field the signature covers must equal the request and the challenge Keeper remembers. **(3) A one-shot challenge this process minted.** `message_display_prepare` mints 32 CSPRNG bytes (unpadded Base64URL, 43 chars) and remembers the context plus `SHA256(IV ‖ ciphertext ‖ tag)` for 30 seconds, capped at 8 live entries per process (`MESSAGE_DISPLAY_BUSY` on a ninth, rather than evicting a reveal the caller does not own), dropped on handle close and with the process. The server signs a permit over a challenge without knowing whether a real Keeper minted it; that binding is checked here, and another Keeper process holds no such entry. Consumption is atomic and sits after verification and before the decrypt, so a bad signature cannot burn a pending reveal, a tag failure cannot be retried against the same authorization, and concurrent replays leave exactly one winner. **(4) Two clocks, one of them with no grace.** The permit window is `issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 30`; the message's own `token_expires_at` gets no skew at all and is re-checked immediately before the response so a late answer cannot display an expired message. Both requests decode strictly — unknown fields, duplicate JSON keys (nested `permit` included), missing fields, and payloads over 16 KiB are `MESSAGE_INVALID_INPUT` before anything is opened. The dispatcher's shared decoder uses `json.Unmarshal`, which keeps the last of a duplicate key; in a signature-bound request that means verifying one `dek_version` and decrypting under another, so these two actions decode through their own `strictDecodeJSON`. Five domain codes (`MESSAGE_INVALID_INPUT`, `MESSAGE_DISPLAY_BUSY`, `MESSAGE_DISPLAY_NOT_AUTHORIZED`, `MESSAGE_DECRYPT_FAILED`, `MESSAGE_EXPIRED`) ride in the existing `error_code` field and are shared verbatim with the server and the Extension. **Known limitations:** a permit proves user-session authorization, not OS process identity and not a human click — a stolen user JWT, app XSS, or a hostile OS is a different threat, and a revocation lands up to 30 seconds late. GCM tag verification is domain separation, not sender authentication: anyone holding the Group DEK can mint a valid message. And the plaintext reaching the browser is the accepted cost of the carve-out, not something Keeper can take back.|
|0.0.30|`conversation_decrypt_batch_for_app_display`|DragPass 1:1 chat reveal, and the second `TestNoRawSecretInResponseTypes` carve-out (after 0.0.29). `conversation_decrypt_batch_for_app_display` returns `plaintext_b64` as a `string[]` parallel to the request batch — approved for exactly that one response type (element type included) in dragpass-control-plane `docs/exec-plans/active/dragpass-chat-1to1-implementation.md` §5 and `docs/security/threat-model.md` §4.10; `TestNoRawSecretInRequestTypes` is unchanged and every clipboard action still returns no plaintext. It widens the 0.0.29 browser-display carve-out from one message to a conversation's worth, and the same four things keep the exception from widening into "the app can decrypt anything the org can". **(1) The AAD is Keeper-built.** The request carries no `aad_b64`, domain, or canonical string; Keeper assembles `dragpass.chat\|1\|<org_id>\|<conversation_id>\|<dek_version>` from the permit's fields, so a drag token (no AAD), a Secure Message (`dragpass.message\|...`), and a credential payload (credential canonical) fail the GCM tag here even with the right handle and the right named conversation. **(2) A server signature, not an action name.** The action requires an RSA-PSS SHA-256 conversation-read-permit over the 9-item canonical `dragpass.chat.read\|1\|account_id\|org_id\|conversation_id\|dek_version\|issued_at\|expires_at\|server_key_version`, verified under the pinned key of the named version; a missing version fails closed, and an MCP service token cannot obtain such a permit. The request's `org_id` / `conversation_id` / `dek_version` must equal the permit's. **(3) Possession, not a challenge.** Unlike the Secure Message reveal there is no per-message challenge and no prepare step: opening the group handle from a wrapped grant is itself the key-possession proof, so one permit opens every message of one conversation at one `dek_version` inside its TTL. **(4) A fixed window and an all-or-nothing batch.** The permit window is `issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 300`; if any message in the batch fails the tag / UTF-8 / AAD the whole batch is refused with no partial plaintext, since one conversation at one version is one key/AAD family. The request decodes strictly — unknown fields, duplicate JSON keys (nested `permit` included), missing fields, a request over 2 MiB, and a batch over 200 messages are `CHAT_INVALID_INPUT` before anything is opened, through the same `strictDecodeJSON` the message actions use. Three domain codes (`CHAT_INVALID_INPUT`, `CHAT_PERMIT_NOT_AUTHORIZED`, `CHAT_DECRYPT_FAILED`) ride in the existing `error_code` field. Plaintexts are zeroized after encoding and never logged. **Known limitations:** a permit proves user-session authorization, not OS process identity and not a human click, and it opens the whole conversation at that version for its TTL rather than one message at a time — the accepted-gap the read-permit takes on in exchange for scroll volume (it binds no message payload digest). GCM tag verification is domain separation, not sender authentication.|
|0.0.41 (current)|`chat_state_*` permit canonical: twelve items at schema `2`|**No new action** — the registered action count stays 85. What changes is the permit every conversation-state action already carries: the one watermark counter (`watermark_next_index`) becomes four slots (`watermark_epoch`, `watermark_leaf_index`, `watermark_next_handshake`, `watermark_next_application`) and the signing string goes from ten items at schema `1` to twelve at schema `2`. **This is a breaking wire change and both sides pin the same literal** — `TestChatStatePermitCanonical_GoldenVector` here and its twin in ariadne — because a permit signed under the old canonical verifies against nothing and every state action answers `CHAT_STATE_NOT_AUTHORIZED`. Four slots because naming a position in an MLS group takes four (RFC 9420 §9.1, §6.3.1), the same widening `chat_state_mark_received` took in 0.0.37. **Only the application axis is compared.** With `encrypt_control_messages` pinned false a Commit leaves as a `PublicMessage` and consumes no ratchet position, so this device never advances its handshake generation; comparing a non-zero handshake watermark against a record that structurally cannot match it would latch the conversation on a number it could never reach. The slot is carried because flipping that setting brings the axis back, and a server inflating it is an availability attack that learns no plaintext. **The leaf slot is judged only once the server has accepted something**: with both counters at zero it names no chain and is ignored, and once either is non-zero the permit's leaf must equal this device's own or the call is refused with `CHAT_STATE_NOT_AUTHORIZED` — a permit describing another leaf's chain must never be used to judge this one's. The refusal is an authorization failure and not a rewind, so it latches nothing. **The keyring anchor gains a `version`**: an anchor written by 0.0.35–0.0.40 has no version field, and its `watermark_next_index` folds into the application axis rather than reading as zero under the renamed field, which is honest because that is the only axis a sender has ever used. **What this buys**: rollback detection that uses an honest, up-to-date server as a second witness — it catches a state file and a keyring anchor restored together from the past while the server's record is current. **What it does not**: a server that also returns a past value, and sends that never reached the server. **What it costs**: `sender_account_id` and `leaf_index` become server plaintext, and RFC 9420 encrypts the leaf inside `SenderData` by design (§6.3.2). Design §7.4 (W2) carries the full table.|
|0.0.40|No protocol change|**No new action** — the registered action count stays 85, and no request or response type changes. The pending / confirmed separation from design §7.3.1–§7.3.3 (M3.8) lands in `internal/keystore/chatstate` as `Store.BeginCommit` and `Store.ConfirmCommit`, behind the `mls` build tag for their MLS half, and nothing exposes them over Native Messaging. **RFC 9420 §14 is the requirement**: "The generation of Commit messages MUST NOT modify a client's state". The previous build broke it in one line — `add_member` called `build()` and `apply_pending_commit()` together — so a device that lost the server's compare-and-set had already moved past the epoch it needed to apply the winner's Commit from. Building now leaves `Record.Epoch`, the send chain and the rollback anchor untouched and puts the Commit in `Record.Pending`; one call moves them, and only on a verdict. **Three outcomes, none of them guessed.** Accepted promotes the pending and releases the Welcome for the first time. Superseded drops the fork with the next-epoch secrets in it and applies the winner's Commit to the epoch that never moved. An unresolved outcome is the absence of the call: the pending stays, a new Commit, a new send and a new MLS open are refused with `ErrCommitPending`, and the caller settles it by asking the server about the unique `client_commit_id` — a retransmission and a local-history re-read are not refused, since neither touches the ratchet or the epoch. **The persistence form is the library's, chosen over holding `CommitSecrets` ourselves**: `Snapshot.pending_commit_snapshot` rides `write_to_storage` / `load_group`, so the fork survives a restart with no second format, a second build is refused by `MlsError::ExistingPendingCommit` and not only by the record, and applying another member's Commit drops ours in the same operation. The price is that the confirmed state and the fork share `Record.GroupState`, so the anchor is kept on the confirmed axis by code: `Record.Epoch` never takes a pending epoch, because written there a lost race would read as a rewind on the next load and latch the conversation. Measured cost of an outstanding fork on a two-member group: **1505 bytes confirmed, 3770 with a pending Commit, 1890 once settled**. **§7.3.4 becomes true on an empty set**: with `encrypt_control_messages` pinned false a Commit is a `PublicMessage`, so it consumes no handshake generation and touches no application generation either — there is no position a losing Commit could have spent. The rule is kept rather than deleted, because flipping the setting brings the axis back. The record layout gains one optional field (`pending`) at **schema version 2 unchanged**: it is absent in a record written by 0.0.39 and absent means "no unsettled Commit", which is what a 0.0.39 record actually says. Six new FFI entry points carry it: `dpmls_group_commit_add_member` (replacing `dpmls_group_add_member`, and additionally reporting the confirmed epoch the Commit was built against — the value the server's CAS compares), `dpmls_group_commit_update`, `dpmls_group_commit_apply`, `dpmls_group_commit_clear`, `dpmls_group_has_pending_commit` and `dpmls_group_epoch`, the last of which reads `Group::current_epoch()` and therefore never reports an epoch only a pending Commit would reach. `panic` stays at `unwind` with `catch_unwind` at every entry point. The Linux release recipe is untouched and still `CGO_ENABLED=0` and static. **What is not here**: the ariadne CAS endpoint, the Native Messaging actions that would carry a verdict across IPC, and the M3.4 watermark.|
|0.0.39|No protocol change|**No new action** — the registered action count stays 85, and no request or response type changes. The send and receive transactions from design §7.2.1 (T-c) and §7.2.2 / §8.4 land in `internal/keystore/chatstate`, behind the `mls` build tag for their MLS half, and nothing exposes them over Native Messaging. **The send order is the point**: the record naming the position is fsynced before the AEAD runs, the encryption is inside the per-conversation lock, and a crash between the two writes abandons that position instead of reissuing it (`next_encryption_key` burns it). Reserving under the lock and encrypting after it — the shape the five existing actions have — does not survive MLS, because the position is decided by the loaded group state and not by the integer the caller carries, so two processes with different reservations can encrypt at the same step. **The receive order is not the mirror**: a decrypt consumes its key and RFC 9420 §9.2 deletes it at once, so the advanced state, the delivery mark and a sealed local copy of the plaintext are confirmed in one file replacement and a re-read comes from that copy. The copy is sealed under a third subkey of the owner's seal key and never written as plaintext; its retention period, its erasers and its home are M4.6.1 / M4.6.2 / M4.6.3 and are still open, so `HistoryPolicy.MaxAge` ships as zero, meaning undecided rather than "kept forever". A sender declares its position in the MLS `authenticated_data` (`dragpass.chat.mls|1|a|<leaf>|<generation>`, covered by both the signature and the AEAD) and a receiver refuses the delivery when the library cannot report the generation it decrypted with, when there is no declaration, or when the two disagree — `None` is never read as zero and the verification is never skipped. The record layout gains two optional fields (`pending_send`, `history`) at **schema version 2 unchanged**: both are absent in a record written by 0.0.38 and absent means "no unfinished send, no local copy", which is what a 0.0.38 record actually says. Four new FFI entry points carry it: `dpmls_group_send_position` (epoch, leaf and generation in one read, replacing the separate peek and epoch calls so the three describe one moment), `dpmls_group_burn_generation` (derives and drops one application key; the key never crosses the ABI), and `authenticated_data` in and out of `dpmls_group_encrypt` / `dpmls_group_process`, the last of which reports the generation as a value plus a known flag rather than one integer. `panic` stays at `unwind` with `catch_unwind` at every entry point; binary size is not bought with `abort`. The Linux release recipe is untouched and still `CGO_ENABLED=0` and static.|
|0.0.38|No protocol change|**No new action** — the registered action count stays 85, and no request or response type changes. The MLS library (mls-rs 0.56.0 with the pure-Rust provider) is linked into the build and its serialized group state now reaches disk through the chat state record's existing whole-file replacement, but nothing exposes any of it over Native Messaging yet: there is no MLS action, and `Record.GroupState` still crosses no IPC in either direction. Two library features are switched on that the defaults leave off, `secret_tree_access` and `export_key_generation`, because the send ordering that comes next has to be able to read the next application generation without consuming it and to burn one whose fate a crash left unknown. `encrypt_control_messages` is pinned to false explicitly rather than inherited from the derived default, so a Commit goes out as a `PublicMessage`: its framing is metadata the server can read, and in exchange the handshake ratchet is never consumed. The whole of it sits behind the `mls` build tag, so the shipped binaries are built exactly as before — the Linux release is still `CGO_ENABLED=0` and still static.|
|0.0.37|`chat_state_mark_received` names the position with four slots|**No new action** — the registered action count stays 85. A received position was `(epoch, chain_index)`, and that pair is not unique in an MLS group: every sender has its own sender ratchet (RFC 9420 §9.1) and each sender has two of them, handshake and application (§6.3.1). Two members' first message of one epoch therefore carried the same pair, and whichever arrived second was judged a redelivery and dropped — an ordinary message lost, not a repeated one suppressed. `reuse_guard` does not cover this: it is a nonce-reuse mitigation for lost or damaged state, not a delivery identifier, and two messages at one generation carry different guards, so the secret tree fails to open rather than deduplicate. The request now carries `epoch`, `sender_leaf_index`, `content_type` (`"handshake"` \| `"application"`) and `generation`; the identifier's fifth slot is the conversation, which is the record itself. `content_type` is a string rather than a small integer so that its zero value is not also one of the two valid answers. The old two-slot shape is **refused, not defaulted**: the strict decoder sees an unknown `chain_index` and three missing keys, so a request naming neither a leaf nor a ratchet cannot reach the store. The record layout moves to **schema version 2**, because a version-1 mark named only `(epoch, chain_index)` and would decode under this layout as leaf 0 generation 0 — the version byte's existing fail-closed path refuses the whole file instead, which is the right outcome for a deduplication set that would otherwise drop live messages. No released build ever wrote one: 0.0.35 and 0.0.36 carry no release tag. **The sending axis is untouched** — `chat_state_reserve_send`, `chat_state_commit_outbox` and `chat_state_read_outbox` keep `chain_index` on the wire, `next_index` and the anchor's reservation ceiling keep their meaning, and rollback detection is unchanged because it compares the record's own `epoch` and `next_index` and never a position.|
|0.0.36|`reset_device_identity` also erases chat state|**No new action** — the registered action count stays 85. `chat_state_purge` shipped in 0.0.35 with no caller anywhere, so the ADR's requirement that a logout and a device reset erase the ratchet state was written down and not wired: a device kept its sealed conversation files, its anchors, and its seal keys through both. This release closes the device-reset half. `reset_device_identity` cannot go through `chat_state_purge`, because that action names an account and a reset is what a user reaches for once the server-side account is gone; it sweeps the state root instead. For the sweep to name each owner's seal key slot, the owner directory and that slot now share one **keyless** tag (`sha256("dragpass.chat.state.owner|1|" || account_id)`) rather than an HMAC under the seal key the sweep is trying to find. `SecretStore` is Get / Set / Delete with no listing, so a slot named by an account id is unreachable from a sweep nobody told which accounts exist; the hygiene is unchanged, since neither form can be walked back to an account id and both are visible only to the user who can already read the keyring. **The ordering is kept**: per owner the anchors and the files go first and the seal key last, because deleting the seal key is what makes a restored backup unopenable, and therefore what stops a purge being used to clear a latched `needs_rekey` and then bring the rewound file back. A failing step no longer stops the ones after it — each stands alone and all of them are idempotent, and aborting would skip exactly the step that makes whatever survived worthless. Inside the reset the purge is best-effort: a failure is logged, not returned, because refusing the reset would block the re-enrollment the action exists for. Erased conversations are not named in `cleared`, which is the Keychain slot list. The logout half is the Extension's, through `chat_state_purge`.|
|0.0.35|`chat_state_reserve_send`, `chat_state_commit_outbox`, `chat_state_read_outbox`, `chat_state_mark_received`, `chat_state_purge`|The storage layer DragPass chat v2's ratchet will sit on. **MLS is not integrated and none of these five encrypts anything** — what they do is decide, durably and under a per-conversation advisory lock, which chain position a sender may use next and which ciphertext a retransmission must reuse. The contract is fixed before the library is chosen because a lost counter reuses a `(key, nonce)` pair no matter which library sits on top, and that is the one failure in this design that cannot be taken back once the ciphertext is out. **The state moved out of the keyring.** `SecretStore` is `Get`/`Set`/`Delete`, so no primitive changes the state body and its rollback anchor together; a Windows Credential Manager entry caps around 2.5 KB, which an MLS group state passes; and it cannot enumerate, which logout-time erasure needs. Papering over the three with chunking, journals, and index entries would put the key-reuse defect in the paper, so the keyring now keeps only a 32-byte seal key per owner and a per-conversation anchor, and the bulk lives in `os.UserConfigDir()/dragpass-keeper/chat-state/` as owner-only sealed files named by an HMAC under a subkey of the seal key. **Owner-only is not one mechanism**: `0600`/`0700` on macOS and Linux, and on Windows — which ignores those bits and would otherwise leave the file at `0666` with inherited ACEs — a protected DACL carrying exactly one access-allowed entry for the token user. `dragpass-keeper.exe` is a released artifact, so this is built rather than skipped, and the tests assert the property through each platform's own mechanism. What it buys on both is the same and is narrow: other users of the machine are kept out, same-user processes are not, and on Windows the owner keeps implicit `WRITE_DAC` anyway. **Be exact about the cost:** at-rest protection for the bulk steps down from the OS keyring to file permissions plus that seal key, and the files enter backups; the seal key remaining in the keyring is what keeps the files alone worthless, and that is a requirement rather than a convenience. Writes are whole-file replacements (temp → fsync → rename → directory fsync) and a temp file is never a load candidate, so a half-written one is harmless; the Windows rename equivalent is **not assumed** and is on the ADR's measure-first list. **Rollback is refused on two axes, and the refusal latches**: the keyring anchor's monotonic `generation` catches a state file restored on its own (a backup of the config directory does not restore the login keychain with it), and a server watermark carried *inside* the signed permit catches a file and an anchor restored together. The rule is "the higher of the two, never the lower", so ariadne stays UNTRUSTED: a lower claim changes nothing and a higher one forces a re-establishment without yielding plaintext. There is no continue-anyway path, deliberately; the only ways out are a new epoch and `chat_state_purge`. **Accepted gap:** a file and anchor restored from the same moment plus a cooperating server defeats both axes, which local state alone cannot close. **Ordering that is not tunable:** `chat_state_reserve_send` fsyncs the consumption before it answers and `chat_state_mark_received` persists before it answers, so a crash loses a message rather than reusing a position, and a redelivery advances the state once rather than twice. Gaps in the chain are ordinary; `fsync` cost is traded away with block reservation (`count` up to 64), never by reordering. `chat_state_commit_outbox` is idempotent on `client_message_id` so a retransmission is the same bytes — re-encrypting a plaintext at a second position is refused by construction. **Four of the five require a server-signed permit** on its own `dragpass.chat.state` domain (10-item canonical, the same fixed 300-second window, strict JSON decode, owner taken from the permit and never from the request), and the directory is opened only after every check passes, so an unauthorized call leaves no state directory at all rather than merely an error. That is what makes the MCP boundary enforcement rather than convention: the dispatcher has one registry and the Keeper cannot tell which of the four surfaces spawned it, but permits are issued on user-JWT routes that the `/api/v1/mcp/*` service token cannot reach, so an MCP process framing these requests by hand cannot produce one. A regression guard pins the MCP-callable set at exactly five actions with no `chat_state_*` among them. It does **not** stop a local attacker already holding a live user session, the same carve-out account key trust states about pins. `chat_state_purge` is the one action with no permit: it only deletes, any local process can already delete the files, and a server round trip would make erasure fail exactly when the user is logging out of a server they cannot reach; the seal key is deleted last so a purge cannot launder a latched rekey requirement and restore the rewound file. **No new carve-out** — nothing here returns plaintext and the opaque group state never crosses IPC in either direction, so `TestNoRawSecretInResponseTypes` and `TestNoRawSecretInRequestTypes` pass unchanged. Seven `CHAT_STATE_*` codes join the domain error set. Serialization and crash behavior are verified with two real subprocesses and a real kill on all three CI platforms, not mocks — `SIGKILL` on unix and `TerminateProcess` on Windows, which is equivalent for what these tests assert since neither runs cleanup or flushes user-space buffers. Approved in dragpass-control-plane `docs/security/adr-ratchet-state-storage.md` (S1–S7).|
|0.0.34|`conversation_decrypt_batch_for_app_display` gains `payload_kind`|Named group rooms v1, the Keeper half (GR1). **No new action** — the registered action count stays 80 — and **no new carve-out entry**: a room's encrypted name rides the existing chat reveal through one added request field. `payload_kind` is an enum of two values (`message`, `room_name`), optional on the wire and defaulting to `message`, so a caller written against 0.0.33 is byte-for-byte unchanged and a 0.0.33 Keeper (whose strict decoder refuses unknown keys) closes a room request with `validation_error` rather than guessing. **The value selects a pair of canonicals, never one of them.** `message` takes the permit canonical `dragpass.chat.read\|1\|…` with the AAD `dragpass.chat\|1\|…`; `room_name` takes `dragpass.room.read\|1\|…` with `dragpass.room\|1\|…`. Verifying a signature in one domain and then opening a tag in the other is the one mistake this action must be unable to make, so the two strings are built by a single call that has no way to return a mixed pair. **Why a second domain at all.** A room's name and its messages are sealed under one conversation DEK at one epoch, so without a domain the server could move a `conversation_messages` row into `conversations.name_ciphertext` and have that message render as the room's title, with no author and no timestamp. Confidentiality is not what breaks — the reader is a member either way — but the room name is the most compressed metadata an org has, and the cost of refusing it is one string. **Why a second permit domain.** A room-list page issues up to 50 name permits at once; if those also opened messages, drawing the sidebar would place server authorization for 50 rooms' entire contents in the browser for 300 seconds. `dragpass.room.read` binds that bundle to "50 titles". Neither permit has a domain *field* — the domain exists only inside the string the signature covers, which is why no separate binding check is needed and why a message permit presented for a room request just fails. **`room_name` carries exactly one entry**, since a room has one name; 0 or 2+ is `CHAT_INVALID_INPUT`, which also stops the second domain from turning into a general batch decrypt. Everything else is unchanged and applies to both kinds: the strict decode and its caps, the request/permit binding, the fixed `issued_at <= now + 5` / `now < expires_at` / `expires_at - issued_at == 300` window, unknown-key-version fail-closed, group-handle possession, all-or-nothing batch refusal with no partial plaintext, and zeroize-after-encode with nothing logged. **The carve-out list stays at two entries**; the existing `ConversationDecryptBatchForAppDisplayResponseData.plaintext_b64` rationale was rewritten to cover N-member rooms and room names, and a test now requires it to name `room_name` and both room domains — widening the behavior while leaving the rationale alone is a contract violation, not a documentation lapse. `TestNoRawSecretInRequestTypes` is unchanged: `payload_kind` is an enum, not secret material. Cross-repo vectors for both domains, including the negative `dragpass.chat` vector over the same (org, conversation, dek_version), are pinned in dragpass-control-plane `docs/testing/fixtures/chat-rooms-v1.json`. **Known limitation:** the domain separates *payload kinds*, not *rooms* — within one room at one epoch, possession of the handle plus a valid permit opens everything of that kind, exactly as 0.0.30 accepted for messages. Approved in dragpass-control-plane `docs/exec-plans/active/dragpass-chat-grouproom-implementation.md` §5 / §6 and `docs/security/threat-model.md` §4.10.|
|0.0.33|`peer_key_chain_evaluate`, `peer_key_owner_reset`; the two wrap actions and the four `peer_key_pin_*` actions gained the owner check|Two defects in account key trust v1, found by an audit of the Extension half and fixed in the Keeper. **The pin namespace was chosen by the adversary.** A pin lives at `peer-pin:<owner>:<peer>`, and the owner half arrives as a request field whose original source is the server (`GET /account/me`). Nothing cross-checked it, so a malicious ariadne that swapped a member's public key *and* reported a different account id sent every lookup into an empty namespace: every peer read as a first observation, TOFU allowed the wrap, `changed` never fired, and the fingerprints a human had verified sat untouched in the old namespace where nothing consulted them. The same lie emptied `peer_key_pin_list` and silently removed the SPA's blocked banner. The Keeper now records the **first** owner id it is ever given, in a single `peer-key-owner` entry beside `peer-key-policy`, and refuses any request carrying a different one with the new `peer_key_owner_mismatch` code — before reading a pin, before writing one, and before producing wrap output. **Be exact about the gain:** this stops a server that *switches* the id later, which is the attack, because the pins worth bypassing were written under the first id. It does not stop a server that lies consistently from first use; that server picks the namespace, and the Keeper has no independent source for an account id to check a first claim against. That case is harmless, because the namespace is only a label and the pins inside it are real pins over real peer fingerprints. `peer_key_owner_reset` is the only path that changes the record and exists for a device two accounts genuinely share; **it must be wired to the extension options page and nothing else**, which the Keeper cannot enforce because it does not know which of the four surfaces spawned it (`docs/security/adr-ratchet-state-storage.md` §3.1), so the restriction is stated as a client obligation. Pins survive a reset. **A signed rotation deadlocked the UI.** The pin only advanced to `rotated` inside a wrap, while the SPA blocked all four wrap entry points whenever the pinned fingerprint differed from the served key, so a legitimate signed rotation locked the org with no call that could show the Keeper the chain. The two escapes the banner offered were both wrong: out-of-band verify lands on `verified` instead of `rotated` and erases the "this key changed" signal (and launders a real substitution just as readily), and forget drops the protection. `peer_key_chain_evaluate` gives the chain somewhere to be judged. It runs **the same** `evaluatePeerKeyTrust` the wrap path runs, with no parallel logic, and persists the pin exactly as the wrap path would; a refusal returns `changed` with both fingerprints and changes nothing. The verdict rides the success envelope because the action succeeded at what it was asked to do, and nothing is lost by that — the wrap remains the enforcement point. It does not widen local attacker power: a caller who can reach the Keeper can already call the wrap actions, which take these same inputs and run this same state machine. **Strict mode does not apply to it**, deliberately: strict mode is a rule about wrapping and this action wraps nothing, refusing there would make the deadlock worse, and a pin the evaluation moved to `rotated` still refuses the next wrap with `peer_key_unverified` until a human verifies it — so reporting the true state hands out no wrap strict mode would have refused. **No new carve-out**: a fingerprint is a hash of public material and `state` / `advanced` / `reset` are metadata, so `TestNoRawSecretInResponseTypes` and `TestNoRawSecretInRequestTypes` both pass unchanged. Approved in dragpass-control-plane `docs/exec-plans/active/account-key-trust-implementation.md` §6.1–§6.5; the audit is dragpass PR #186.|
|0.0.32|`peer_key_policy_get`, `peer_key_policy_set`|Strict mode for account key trust v1: a device-local policy, **off by default**, that narrows the wrap path from "is this the key I accepted" to "did a human actually compare it". 0.0.31 made an unexplained key change refuse; this release lets a device also refuse a key that changed in no suspicious way and that nobody has checked. `require_verified_peers` on means a wrap to any peer whose pin is not `verified` closes with `peer_key_unverified`, produces no wrap output, and leaves the pin untouched — a first observation with no pin yet, a `tofu` pin, and a `rotated` pin whose chain verified all land there. The first of those is the one it would be worst to let through, since it is the wrap that hands the Group DEK to a key nobody looked at. The batch action refuses whole, exactly as it does for `changed`, so a rotation does not wrap ten members before stopping at the eleventh. `changed` keeps its own code and its two fingerprints with the toggle in either position: the state machine decides what the key is and the policy only decides how much the device insists on before wrapping to it, which is also why the check runs after the state machine rather than inside it. A call that names no account id has no pin to judge and is unaffected. **The policy is per device, not per owner** — one `peer-key-policy` entry under `config.Service`, read once per enforced call so a rotation cannot judge some members under one answer and some under another. Two accounts sharing a machine share the setting and keep separate pins. **The server can neither read nor write it**: nothing on the account backs it, no action reads it on the server's behalf, and the extension options page is the only caller, so a compromised server cannot quietly turn off the check that exists to catch it. `require_verified_peers` is required on `peer_key_policy_set` rather than defaulted, so a malformed payload is `validation_error` instead of a silent switch-off. `peer_key_unverified` was already in the `error_code` enum, reserved by 0.0.31; this is the release that starts returning it. **No new carve-out**: the policy response carries one boolean, so `TestNoRawSecretInResponseTypes` and `TestNoRawSecretInRequestTypes` both pass unchanged. **Known limitation:** strict mode is device-local like the pins it reads, so a new device starts with the policy off and every peer back at TOFU. Approved in dragpass-control-plane `docs/exec-plans/active/account-key-trust-implementation.md` §6.5 (KT7).|
|0.0.31|`peer_key_pin_list`, `peer_key_pin_get`, `peer_key_pin_verify`, `peer_key_pin_forget`; `dek_rewrap_for_member` and `dek_unwrap_and_rewrap_for_many` widened; `rotate_user_keypair_prepare`, `generatekeypairwithrecoverywrap`, and `auth_recovery_prepare` widened|Account key trust v1. Every Group DEK the Extension wraps to a member is wrapped to a public key the **server** chose, and nothing checked that the server kept choosing the same one. The threat model classifies ariadne as UNTRUSTED, so anyone who can write `accounts.public_key` — an operator, a DB compromise, a server-side bug — could have a Group DEK wrapped to their own key, and one Group DEK opens every drag token, Secure Message, and credential payload in that group. This release closes that with a pin: one keyring entry per (owner, peer) holding the fingerprint already accepted, checked at the only place a substituted key is actually used. **Enforcement is in the Keeper**, not the server API and not the Extension, because the adversary is a malicious server; an Extension already compromised has easier routes than omitting an account id. **Four new actions** manage pins and return no key material — fingerprints, state words, three timestamps. `peer_key_pin_verify` takes a PEM precisely so it can refuse to take the caller's word for what that PEM hashes to: confirm fingerprint A while the server serves B and it fails `crypto_failure` with the pin untouched. **Two wrap actions gained enforcement.** `dek_rewrap_for_member` takes `owner_account_id` / `other_account_id` / `rotation_statements`; `dek_unwrap_and_rewrap_for_many` gains a `recipients[]` shape carrying the same per-recipient fields, mutually exclusive with the pre-0.0.31 `recipient_public_keys[]`, which still works and is never enforced. Both responses gain `pin_enforced` plus `pin_state` / `pin_states`. The account ids are optional only as a compatibility device: this Extension sends them from all four wrap call sites, and `pin_enforced:false` is a regression signal rather than a supported mode. **Every recipient is judged before the first wrap**, so one refusal produces no partial output — a rotation that wrapped ten members and refused the eleventh would leave the org holding two DEKs. Caps: 64 recipients, 32 statements each, 512 KiB per request, checked by the dispatcher before decode. **The state machine** is a pure function: no pin → `tofu` and allow; pin matches → keep the state and allow; pin differs with a chain that starts at the pin, ends at the observed key, links end to end, names the right account, carries fingerprints its own public keys hash to, and verifies both RSA-PSS signatures over `dragpass.keyrotation\|1\|<account_id>\|<old_fp>\|<new_fp>\|<rotated_at>\|<reason>` → `rotated`, allow, and `verified` does not survive; anything else → `peer_key_changed` with no output and no pin mutation. `compromise` anywhere forces `changed`, since the holder is saying the old key is in someone else's hands and the earlier links may be the attacker's; `recovery` behaves exactly like `voluntary`. **Rotation and recovery now produce statements.** The three fields on `rotate_user_keypair_prepare` are required, not optional: a key change with no statement drops every observer's pin to `changed` and locks the account out of invites, rotations, and DMs across the org. Recovery produces one too, because RK24 recovery changes `accounts.public_key` — without it a normal operational flow would cause exactly that org-wide lockout. Its `reason` is fixed to `recovery` by the Keeper with no field for a caller to set, and its OLD half is signed through the `recovery_handle` that already holds the OLD private key, with the OLD public key derived from that same private key rather than read from the Keychain. The existing challenge signatures are untouched: they prove key ownership to the server, while the statement proves it to peers who never see the challenge. **Fingerprint formula:** `hex(sha256(pem bytes))`, over the PEM exactly as received, with no normalization on any side — the Extension, the server, and the Keeper hash the same bytes and a single added newline would split them silently. Deliberately not the `account_device_keys` formula (`sha256` of the Base64 *string*), which stays an internal identifier; `docs/testing/fixtures/account-key-trust-v1.json` pins both so the wrong one is caught. **No new carve-out.** `TestNoRawSecretInResponseTypes` and `TestNoRawSecretInRequestTypes` both pass unchanged: a fingerprint is a hash of public material, and `state` / `pin_enforced` / the timestamps are metadata. `peer_key_changed` and `peer_key_unverified` join the `error_code` enum; the second is reserved for the strict-mode toggle, which ships separately. **Known limitations:** an attacker holding the OLD private key can forge a `voluntary` statement and the pin advances to `rotated` quietly — the pin stops a server-only compromise, not a stolen user key, and the designed answer to the latter is the holder rotating with `reason=compromise` to drop every peer to `changed`. A stolen RK24 can likewise mint a legitimate `recovery` statement; that is account takeover, the same class as OLD key theft. Pins are device-local, so a new device starts at TOFU again. The org archive key recipient is exempt (`exempt` in `pin_states`) because it is an org resource with no account to pin against, so a swapped archive public key can still receive an OLD Group DEK. `owner_account_id` is scoping, not authorization. Approved in dragpass-control-plane `docs/exec-plans/active/account-key-trust-implementation.md` §6 and `docs/security/threat-model.md` §4.11.|
|0.0.27|`credential_http_request` query injection (`query_template`)|Opens the `query_key` credential preset for APIs that take the key as a query parameter instead of a header. `query_template` is added to both the request and the signed policy, carrying the same `{{secret.<key>}}` placeholders as `header_template`; the rendered values are appended to `target_url`'s query and `target_url` itself is never template-substituted. The canonical policy string appends `query_template` **only when it is non-empty**, so every header / cookie policy signs the exact bytes it did in 0.0.26 and signatures made by an older server still verify — this release and the ariadne `sign.go` change are one window. `queryTemplatesEqual` (sibling of `headerTemplatesEqual`) refuses a request whose template differs from the signed one, and `Validate` now requires at least one non-empty template instead of a non-empty `header_template`. Fail-closed rules: an unparseable target or existing query, an empty or non-printable parameter name, a name `target_url`'s query already carries (which of a repeated pair the server reads is not the Keeper's to decide), and a rendered value carrying CR / LF or any other non-printable byte. More than one parameter is allowed — every name and value comes from the signature-bound policy, so a count cap would add nothing the signature does not already give. Injected query values join the `injected` set, so `redactionVariants` / `maskSecrets` cover a query secret echoed back percent-encoded. The post-injection URL carries the credential in the clear, so transport errors are reduced to their cause (`unwrapURLError`) before leaving the handler — `*url.Error` embeds the request URL verbatim — and the handler masks what remains. `query_template` matches no raw-secret pattern, so the no-raw-secret guards pass with no new carve-out. **Known limitation:** the signature canonical covers `target_path` only, not the query string (`executionTargetMatches` compares `EscapedPath()`), so the parameters `query_template` injects are inside the signature but any query the agent adds is not — `allow_query` is the only switch on that door. And a query credential lands in the target's access log and in every proxy in between, which Keeper redaction cannot reach; prefer a header when the target API supports one.|
|0.0.24|`auth_signup_prepare`, `auth_recovery_prepare`, `auth_recovery_reissue_prepare`|Removes native RK24 display and platform UI capability actions. New RK24 values are request-only inputs, and responses no longer contain display handles.|
|0.0.20|`credential_approval_prompt`|Adds server-challenge-bound native approval and device-signed decisions for MCP credential use. Generic request-key signing paths reject this decision namespace.|
|0.0.21|No protocol change|Keeps release SBOM material outside the checkout so GoReleaser can publish the Homebrew archive and tap update from a clean git tree.|
|0.0.22|Remove unused native prompts|Credential approval is owned by the DragPass browser app. Removes `credential_approval_prompt` and the unused secret-input and confirmation capabilities. Keeper retains native recovery-key display, cryptographic policy enforcement, and credential injection.|
|0.0.23|Remove legacy compatibility paths|Removes the unused password-only DEK action, duplicate session error wrappers, and the unversioned server public key slot. Server key reads now resolve through the active version pointer only.|

The Extension and MCP client enforce their own `MIN_KEEPER_VERSION`.
Keeper-down or below-min sets a red
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
