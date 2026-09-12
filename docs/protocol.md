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

The current production backend is macOS Cocoa. Keeper exposes no approval or
confirmation action. Native UI is limited to recovery-key display through
composite auth actions that return encrypted or public material rather than RK24 text.

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
|`auth_recovery_begin`|`alias`, `recovery_key`|`{ recovery_auth_seed, entered_recovery_key_handle, entered_recovery_key_expires_at_ms }`|Accepts the RK24 entered in the App, derives only the server authentication seed, and immediately stores the RK24 behind an opaque short-lived handle for the prepare step. The response never contains RK24 or its wrap key.|
|`auth_recovery_prepare`|`alias`, `entered_recovery_key_handle`, `challenge_token`, `signature`, `wrapped_keeper_b64`, `recovery_key_version`, `server_key_version?`, `new_recovery_key`|`{ old_challenge_signature, recovery_handle, recovery_expires_at_ms, new_publickey, new_recovery_auth_seed, new_recovery_wrapped_keeper, new_recovery_key_version }`|Verifies the server-signed recovery challenge, restores the old private key into a recovery session, and derives the replacement identity material from a request-only new RK24.|

### Group DEK

|Action|Request fields|Response fields|Description|
|---|---|---|---|
|`dek_rewrap_with_old_key`|`challenge_token`, `signature`, `recovery_handle`, `encrypted_group_dek`, `new_public_key`, `server_key_version?`|`{ new_encrypted_group_dek }`|Synthetic action — unwrap+wrap in Keeper. raw bytes never leave (R4 fix-forward).|
|`group_dek_generate_and_open`|`my_public_key`|`{ group_handle, expires_at_ms, encrypted_for_me_b64 }`|Generate new 32B Group DEK + register as session + RSA-wrap with caller pubkey. raw never leaves.|
|`dek_rewrap_for_member`|`wrapped_for_me_b64`, `other_public_key`|`{ encrypted_for_other_b64 }`|Synthetic unwrap+wrap. raw stays in Keeper memory only.|
|`dek_unwrap_and_rewrap_for_many`|`wrapped_for_me_b64`, `recipient_public_keys[]`|`{ encrypted_for_recipients_b64[] }`|Multi-recipient variant of `dek_rewrap_for_member`. Unwrap my wrapped Group DEK once, RSA-OAEP re-wrap to each recipient key; response list is parallel to the request keys. raw unwrapped once, stays in Keeper memory only. Used by `adminRotateDek` to wrap the OLD Group DEK to every member + the archive key without the raw entering the JS heap.|
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
|0.0.29 (current)|`message_display_prepare`, `group_decrypt_with_aad_for_app_display`|Secure Message Overlay display path, and the first `TestNoRawSecretInResponseTypes` carve-out since 0.0.11. `group_decrypt_with_aad_for_app_display` returns `plaintext_b64` — the protocol's only plaintext-returning response, approved for exactly that one response type in dragpass-control-plane `docs/security/secure-message-overlay-proposed-boundary.md`; `TestNoRawSecretInRequestTypes` is unchanged and every clipboard action still returns no plaintext. Four things keep the exception from widening into "the app can decrypt anything the org can". **(1) The AAD is Keeper-built.** Neither request carries `aad_b64`, a domain, or a canonical string; Keeper assembles `dragpass.message\|1\|<org_id>\|<group_id>\|<dek_version>\|<token_expires_at>` from fields it validated, so a drag token (no AAD) and a credential payload (credential canonical) fail the GCM tag here even with the right handle and the right named context. **(2) A server signature, not an action name.** The dispatcher does not distinguish app from MCP per action, so a new action name is not an authentication mechanism. `group_decrypt_with_aad_for_app_display` requires an RSA-PSS SHA-256 permit over the 14-item canonical above, verified under the pinned key of the named version; a missing version fails closed, and an MCP service token cannot obtain such a permit. Every field the signature covers must equal the request and the challenge Keeper remembers. **(3) A one-shot challenge this process minted.** `message_display_prepare` mints 32 CSPRNG bytes (unpadded Base64URL, 43 chars) and remembers the context plus `SHA256(IV ‖ ciphertext ‖ tag)` for 30 seconds, capped at 8 live entries per process (`MESSAGE_DISPLAY_BUSY` on a ninth, rather than evicting a reveal the caller does not own), dropped on handle close and with the process. The server signs a permit over a challenge without knowing whether a real Keeper minted it; that binding is checked here, and another Keeper process holds no such entry. Consumption is atomic and sits after verification and before the decrypt, so a bad signature cannot burn a pending reveal, a tag failure cannot be retried against the same authorization, and concurrent replays leave exactly one winner. **(4) Two clocks, one of them with no grace.** The permit window is `issued_at <= now + 5`, `now < expires_at`, `expires_at - issued_at == 30`; the message's own `token_expires_at` gets no skew at all and is re-checked immediately before the response so a late answer cannot display an expired message. Both requests decode strictly — unknown fields, duplicate JSON keys (nested `permit` included), missing fields, and payloads over 16 KiB are `MESSAGE_INVALID_INPUT` before anything is opened. The dispatcher's shared decoder uses `json.Unmarshal`, which keeps the last of a duplicate key; in a signature-bound request that means verifying one `dek_version` and decrypting under another, so these two actions decode through their own `strictDecodeJSON`. Five domain codes (`MESSAGE_INVALID_INPUT`, `MESSAGE_DISPLAY_BUSY`, `MESSAGE_DISPLAY_NOT_AUTHORIZED`, `MESSAGE_DECRYPT_FAILED`, `MESSAGE_EXPIRED`) ride in the existing `error_code` field and are shared verbatim with the server and the Extension. **Known limitations:** a permit proves user-session authorization, not OS process identity and not a human click — a stolen user JWT, app XSS, or a hostile OS is a different threat, and a revocation lands up to 30 seconds late. GCM tag verification is domain separation, not sender authentication: anyone holding the Group DEK can mint a valid message. And the plaintext reaching the browser is the accepted cost of the carve-out, not something Keeper can take back.|
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
