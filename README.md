# DragPass Keeper

The open-source native key-custody helper for the [DragPass Chrome Extension](https://chromewebstore.google.com/detail/blindfold/cmgjlocmnppfpknaipdfodjhbplnhimk?hl=ko&utm_source=ext_sidebar) (**v1.0.2**). It performs the RSA / AES crypto and holds private key material so that keys never enter the browser, which is what makes DragPass's end-to-end encryption verifiable.

<sub>English | [한국어](README.ko.md) | [日本語](README.ja.md)</sub>

Licensed under [Apache-2.0](LICENSE).

The helper secures device keys in OS-native encrypted vaults:

- **macOS**: Keychain
- **Linux**: Secret Service API (GNOME Keyring / KDE Wallet)
- **Windows**: Credential Manager

## Download

Download the latest release from the [Releases page](https://github.com/dragpass/keeper/releases).

### Available Packages

- **macOS**:
  - `dragpass-keeper-macos-x86_64.pkg` (Intel)
  - `dragpass-keeper-macos-arm64.pkg` (Apple Silicon)
- **Linux**:
  - `dragpass-keeper-linux-x86_64.deb` (x86_64/amd64)
  - `dragpass-keeper-linux-arm64.deb` (ARM64)
- **Windows**: `dragpass-keeper.exe` (x64 installer)

## Verifying Downloads

All release packages are signed with GPG for security. We strongly recommend verifying the integrity of downloaded files.

### 1. Import the Public Key

```bash
# Download and import the public key
curl https://raw.githubusercontent.com/dragpass/keeper/main/GPG_PUBLIC_KEY.asc | gpg --import
```

Or import manually from [GPG_PUBLIC_KEY.asc](GPG_PUBLIC_KEY.asc).

**Key Fingerprint**: `66DF 4017 8A5F 6F66 EAAF 318A 3FC4 1856 9192 8FDC`

### 2. Verify the Signature

```bash
# For macOS (Intel)
gpg --verify dragpass-keeper-macos-x86_64.pkg.sig dragpass-keeper-macos-x86_64.pkg

# For macOS (Apple Silicon)
gpg --verify dragpass-keeper-macos-arm64.pkg.sig dragpass-keeper-macos-arm64.pkg

# For Linux (x86_64)
gpg --verify dragpass-keeper-linux-x86_64.deb.sig dragpass-keeper-linux-x86_64.deb

# For Linux (ARM64)
gpg --verify dragpass-keeper-linux-arm64.deb.sig dragpass-keeper-linux-arm64.deb

# For Windows
gpg --verify dragpass-keeper.exe.sig dragpass-keeper.exe
```

You should see output like:
```
gpg: Good signature from "JinHyeok Hong <vjinhyeokv@gmail.com>" [ultimate]
```

## Installation Output

### macOS

After installing the `.pkg` file, the following files are created:

- `/Library/Application Support/DragPass/dragpass-keeper` - Main executable
- `/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json` - Chrome Native Messaging manifest

**Key Storage**: macOS Keychain

### Linux

After installing the `.deb` file, the following files are created:

- `/opt/dragpass/dragpass-keeper` - Main executable
- `/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json` - Chrome manifest
- `/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json` - Chromium manifest

**Key Storage**: Secret Service API (GNOME Keyring / KDE Wallet)

### Windows

After running the `.exe` installer, the following files are created:

**64-bit System:**
- `C:\Program Files\DragPass\`
  - `dragpass-keeper.exe` - Main executable
  - `com.dragpass.keeper.json` - Chrome Native Messaging manifest
  - `unins000.exe` - Uninstaller
  - `unins000.dat` - Uninstaller data

**32-bit System:**
- `C:\Program Files (x86)\DragPass\`
  - `dragpass-keeper.exe` - Main executable
  - `com.dragpass.keeper.json` - Chrome Native Messaging manifest
  - `unins000.exe` - Uninstaller
  - `unins000.dat` - Uninstaller data

**Key Storage**: Windows Credential Manager

## API Reference

DragPass Keeper communicates with the Chrome extension via Native Messaging protocol. All messages use an **envelope pattern** for better type safety and extensibility.

### Message Format

**Request (Envelope Pattern):**
```json
{
  "action": "action_name",
  "payload": {
    // action-specific fields
  }
}
```

**Success Response:**
```json
{
  "success": true,
  "data": {
    // action-specific response data
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "error message"
}
```

---

### Health Check

#### `ping` - Health Check

Check if the DragPass Keeper is running and responsive.

**Request:**
```json
{
  "action": "ping"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "0.0.1",
    "hash": "binary_sha256_hash",
    "path": "/path/to/dragpass-keeper"
  }
}
```

---

### Device Key Management

#### `savedevicekey` - Save Device Key

Stores the device encryption key in the OS keystore.

**Request:**
```json
{
  "action": "savedevicekey",
  "payload": {
    "key": "base64_encoded_device_key"
  }
}
```

**Response:**
```json
{
  "success": true
}
```

---

#### `getdevicekey` - Get Device Key

Retrieves the stored device encryption key.

**Request:**
```json
{
  "action": "getdevicekey"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "key": "base64_encoded_device_key"
  }
}
```

---

#### `deletedevicekey` - Delete Device Key

Removes the device encryption key from the keystore.

**Request:**
```json
{
  "action": "deletedevicekey"
}
```

**Response:**
```json
{
  "success": true
}
```

---

### Keypair Management

#### `generatekeypair` - Generate RSA Keypair

Generates a new RSA-2048 keypair for the Helper. Requires server signature verification.

**Request:**
```json
{
  "action": "generatekeypair",
  "payload": {
    "challenge_token": "server_provided_challenge_token",
    "signature": "base64_server_signature"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**Notes:**
- Verifies the signature using the server's public key
- Deletes existing session code and keypair before generating new one
- Stores both private and public keys in the OS keystore

---

#### `getpublickey` - Get Helper Public Key

Retrieves the Helper's public key.

**Request:**
```json
{
  "action": "getpublickey"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

---

#### `getserverpubkey` - Get Server Public Key

Retrieves the server's public key that is stored in the OS keystore.

**Request:**
```json
{
  "action": "getserverpubkey"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**Notes:**
- The server public key is hardcoded in the binary and initialized on first run
- This key is used to verify signatures from the server
- Stored in OS-native keystore for retrieval

---

### Session Code Management

#### `savesessioncode` - Save Encrypted Session Code

Promotes pending keypair to permanent storage and saves the session code. Used during both signup and login-on-another-device flows.

**Request:**
```json
{
  "action": "savesessioncode",
  "payload": {
    "encrypted_session_code": "base64_encrypted_session_code",
    "signature": "base64_server_signature"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session_code": "decrypted_session_code"
  }
}
```

**Process:**
1. Verifies signature using server's public key
2. **Promotes pending keypair to permanent storage** (if exists from signup)
   - Signup flow: Pending keypair exists → Promoted
   - Login-on-another-device flow: No pending keypair → Skipped
3. Decrypts the session code using Helper's private key (RSA-OAEP with SHA-256)
4. Stores the decrypted session code in the OS keystore
5. Returns the decrypted session code

**Notes:**
- This action completes the two-phase commit for signup keypair lifecycle
- Safe for both signup and login-on-another-device flows

---

#### `getsessioncode` - Get Session Code

Retrieves the stored session code.

**Request:**
```json
{
  "action": "getsessioncode"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session_code": "stored_session_code"
  }
}
```

---

### Signup Flow

#### `signalias` - Sign User Alias

Generates a keypair and signs the user alias. Used during signup. Uses **pending storage** to prevent orphaned keys if signup fails.

**Request:**
```json
{
  "action": "signalias",
  "payload": {
    "alias": "user_alias"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_signature",
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**Process:**
1. Checks if device is already registered (keypair + session code exist)
2. Generates a new RSA-2048 keypair
3. Stores keypair in **pending storage** (not permanent yet)
4. Signs the alias using the pending private key (RSA PKCS#1 v1.5 with SHA-256)
5. Returns the signature and pending public key

**Notes:**
- Keypair is stored in pending storage and will be promoted to permanent storage by `savesessioncode`
- If signup fails (e.g., 409 Conflict), the pending keypair can be safely overwritten on retry
- This prevents orphaned keypairs in the OS keystore when signup fails

---

### Login Flow

#### `signaliaswithtimestamp` - Sign Alias with Timestamp

Signs the user alias with current timestamp. Used for login authentication.

**Request:**
```json
{
  "action": "signaliaswithtimestamp",
  "payload": {
    "alias": "user_alias"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_signature",
    "timestamp": 1234567890
  }
}
```

**Process:**
1. Generates current Unix timestamp
2. Creates payload: `"alias:timestamp"`
3. Signs the payload using Helper's private key
4. Returns the signature and timestamp

---

#### `signchallengetoken` - Sign Challenge Token

Verifies and signs a challenge token. Used for login verification.

**Request:**
```json
{
  "action": "signchallengetoken",
  "payload": {
    "challenge_token": "server_challenge_token",
    "signature": "base64_server_signature"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_helper_signature"
  }
}
```

**Process:**
1. Verifies the server's signature on the challenge token using server's public key
2. Signs the challenge token using Helper's private key
3. Returns the Helper's signature

---

## Cryptographic Details

### Key Formats
- **RSA Key Size**: 2048 bits
- **Private Key Format**: PKCS#8 PEM
- **Public Key Format**: PKIX PEM

### Algorithms
- **Signature Algorithm**: RSA PKCS#1 v1.5 with SHA-256
- **Encryption Algorithm**: RSA-OAEP with SHA-256
- **Hash Function**: SHA-256

### Key Storage Locations

**macOS Keychain:**
```
Service: com.dragpass.keeper
Items:
- server_public_key (DragPassServerPublicKey)
- keeper_private_key (DragPassKeeperPrivateKey)
- keeper_public_key (DragPassKeeperPublicKey)
- pending_keeper_private_key (PendingDragPassKeeperPrivateKey) - Temporary during signup
- pending_keeper_public_key (PendingDragPassKeeperPublicKey) - Temporary during signup
- device_key (DeviceKey)
- session_code (SessionCode)
```

**Linux Secret Service:**
```
Collection: default keyring
Schema: com.dragpass.keeper
Items:
- server_public_key (DragPassServerPublicKey)
- keeper_private_key (DragPassKeeperPrivateKey)
- keeper_public_key (DragPassKeeperPublicKey)
- pending_keeper_private_key (PendingDragPassKeeperPrivateKey) - Temporary during signup
- pending_keeper_public_key (PendingDragPassKeeperPublicKey) - Temporary during signup
- device_key (DeviceKey)
- session_code (SessionCode)
```

**Windows Credential Manager:**
```
Target Prefix: com.dragpass.keeper
Credentials:
- server_public_key (DragPassServerPublicKey)
- keeper_private_key (DragPassKeeperPrivateKey)
- keeper_public_key (DragPassKeeperPublicKey)
- pending_keeper_private_key (PendingDragPassKeeperPrivateKey) - Temporary during signup
- pending_keeper_public_key (PendingDragPassKeeperPublicKey) - Temporary during signup
- device_key (DeviceKey)
- session_code (SessionCode)
```

**Notes:**
- Pending keys are automatically deleted after promotion to permanent storage
- Pending keys prevent orphaned keys when signup fails (e.g., 409 Conflict errors)

## Test Mode (KEEPER_E2E_MODE)

For end-to-end tests that need to exercise the full signup/login flow without
touching the user's real OS Keychain, set `KEEPER_E2E_MODE=1` in the
environment that spawns the Keeper process. When enabled:

- `main.init()` calls `keyring.MockInit()` from `github.com/zalando/go-keyring`
- All `keyring.Set/Get/Delete` operations go to a process-local in-memory map
- `EnsureServerPublicKey` writes the hardcoded server pubkey into the mock
- The OS Keychain is never read or written
- Process exit clears all keys (perfect test isolation)

Stderr logs `KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)`
on startup so accidental activation in production is easy to spot.

**Production builds are unaffected** — the env variable is checked at runtime,
so the same binary works in both modes.

### KEEPER_E2E_KEYRING_FILE (multi-process keyring sharing)

`KEEPER_E2E_MODE=1` alone uses a process-local in-memory map. When the
Extension's popup and service worker (SW) each spawn their own Keeper process
via `connectNative`, they get separate mock keyrings — signup persists a
keypair in the popup's Keeper, but the SW's Keeper sees an empty keyring and
fails ADMIN_CREATE_ORG with "secret not found".

Setting `KEEPER_E2E_KEYRING_FILE=/path/to/keyring.json` *in addition to*
`KEEPER_E2E_MODE=1` makes `storage.go` mirror every Set/Get/Delete to a JSON
file (`internal/keystore/krfile.go`). All Keeper processes that share the
same file path now see the same keyring entries. The file is loaded into the
mock map at startup and rewritten on every Set/Delete.

This flag is opt-in and only meaningful with the mock provider active. It
does not enable file storage in production builds. The automation fixture
generates a per-test path under `user-data-dir/e2e-keyring.json` so test
runs are isolated from each other.

## Production Clipboard Smoke (DRAGPASS_KEEPER_CLIPBOARD_E2E)

`internal/keystore/clipboard` ships an opt-in smoke/e2e suite that exercises the
real OS clipboard backend (`golang.design/x/clipboard`). It is **off by default**
so `go test ./...` never touches the developer's clipboard.

To run it:

```bash
make test-clipboard-e2e
# equivalent to:
DRAGPASS_KEEPER_CLIPBOARD_E2E=1 \
  go test ./internal/keystore/clipboard -count=1 -run ProductionSmoke -v
```

What it verifies:

- `OSClipboard.Write` actually lands a sentinel string on the OS clipboard.
- TTL expiry clears the sentinel (best-effort, `compare-then-clear`).
- TTL expiry does **not** clobber a value the user copied during the TTL
  window — the SHA-256 compare-and-clear invariant from `production.go`.

Cleanup restores the clipboard contents read at the start of the test, so a
clean run leaves the system clipboard untouched. The suite is intended for
OS-specific local checks and per-OS CI smoke jobs, not the default test job.
