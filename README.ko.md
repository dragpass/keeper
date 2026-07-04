# DragPass Keeper

[DragPass Chrome Extension](https://chromewebstore.google.com/detail/blindfold/cmgjlocmnppfpknaipdfodjhbplnhimk?hl=ko&utm_source=ext_sidebar)(**v1.0.2**)을 위한 오픈소스 네이티브 키 보관 헬퍼입니다. RSA / AES 암호 연산을 수행하고 개인키 자료를 보관해, 키가 브라우저 안으로 들어오지 않도록 합니다. 이것이 바로 DragPass의 종단간 암호화를 검증 가능하게 만드는 핵심입니다.

<sub>[English](README.md) | 한국어 | [日本語](README.ja.md)</sub>

라이선스는 [Apache-2.0](LICENSE)입니다.

헬퍼는 기기 키를 OS 기본 암호화 저장소에 안전하게 보관합니다.

- **macOS**: Keychain
- **Linux**: Secret Service API (GNOME Keyring / KDE Wallet)
- **Windows**: Credential Manager

## Download

최신 릴리스는 [Releases page](https://github.com/dragpass/keeper/releases)에서 내려받을 수 있습니다.

### Available Packages

- **macOS**:
  - `dragpass-keeper-macos-x86_64.pkg` (Intel)
  - `dragpass-keeper-macos-arm64.pkg` (Apple Silicon)
- **Linux**:
  - `dragpass-keeper-linux-x86_64.deb` (x86_64/amd64)
  - `dragpass-keeper-linux-arm64.deb` (ARM64)
- **Windows**: `dragpass-keeper.exe` (x64 installer)

## Verifying Downloads

모든 릴리스 패키지는 보안을 위해 GPG로 서명되어 있습니다. 내려받은 파일의 무결성을 반드시 검증하시길 강력히 권장합니다.

### 1. Import the Public Key

```bash
# Download and import the public key
curl https://raw.githubusercontent.com/dragpass/keeper/main/GPG_PUBLIC_KEY.asc | gpg --import
```

또는 [GPG_KEYSPUBLIC_KEY.asc](GPG_PUBLIC_KEY.asc)에서 직접 가져올 수도 있습니다.

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

다음과 같은 출력이 표시되어야 합니다.
```
gpg: Good signature from "JinHyeok Hong <vjinhyeokv@gmail.com>" [ultimate]
```

## Installation Output

### macOS

`.pkg` 파일을 설치하면 다음 파일들이 생성됩니다.

- `/Library/Application Support/DragPass/dragpass-keeper` - Main executable
- `/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json` - Chrome Native Messaging manifest

**Key Storage**: macOS Keychain

### Linux

`.deb` 파일을 설치하면 다음 파일들이 생성됩니다.

- `/opt/dragpass/dragpass-keeper` - Main executable
- `/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json` - Chrome manifest
- `/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json` - Chromium manifest

**Key Storage**: Secret Service API (GNOME Keyring / KDE Wallet)

### Windows

`.exe` 설치 프로그램을 실행하면 다음 파일들이 생성됩니다.

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

DragPass Keeper는 Native Messaging 프로토콜을 통해 Chrome 확장과 통신합니다. 모든 메시지는 타입 안전성과 확장성을 높이기 위해 **envelope 패턴**을 사용합니다.

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

DragPass Keeper가 실행 중이며 정상적으로 응답하는지 확인합니다.

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
    "version": "0.0.6",
    "hash": "binary_sha256_hash",
    "path": "/path/to/dragpass-keeper"
  }
}
```

---

### Device Key Management

#### `savedevicekey` - Save Device Key

기기 암호화 키를 OS 키스토어에 저장합니다.

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

저장된 기기 암호화 키를 가져옵니다.

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

키스토어에서 기기 암호화 키를 삭제합니다.

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

헬퍼용 RSA-2048 키쌍을 새로 생성합니다. 서버 서명 검증이 필요합니다.

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
- 서버 공개키로 서명을 검증합니다
- 새 키쌍을 생성하기 전에 기존 세션 코드와 키쌍을 삭제합니다
- 개인키와 공개키를 모두 OS 키스토어에 저장합니다

---

#### `getpublickey` - Get Helper Public Key

헬퍼의 공개키를 가져옵니다.

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

OS 키스토어에 저장된 서버 공개키를 가져옵니다.

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
- 서버 공개키는 바이너리에 하드코딩되어 있으며 최초 실행 시 초기화됩니다
- 이 키는 서버가 보낸 서명을 검증하는 데 사용됩니다
- 이후 조회를 위해 OS 기본 키스토어에 저장됩니다

---

### Session Code Management

#### `savesessioncode` - Save Encrypted Session Code

대기 중인 키쌍을 영구 저장소로 승격하고 세션 코드를 저장합니다. 회원가입 흐름과 다른 기기 로그인 흐름 모두에서 사용됩니다.

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
1. 서버 공개키로 서명을 검증합니다
2. **대기 중인 키쌍을 영구 저장소로 승격합니다** (회원가입에서 생성된 키쌍이 있는 경우)
   - 회원가입 흐름: 대기 중인 키쌍 존재 → 승격
   - 다른 기기 로그인 흐름: 대기 중인 키쌍 없음 → 건너뜀
3. 헬퍼의 개인키로 세션 코드를 복호화합니다 (RSA-OAEP with SHA-256)
4. 복호화된 세션 코드를 OS 키스토어에 저장합니다
5. 복호화된 세션 코드를 반환합니다

**Notes:**
- 이 액션은 회원가입 키쌍 생명주기의 2단계 커밋(two-phase commit)을 완료합니다
- 회원가입 흐름과 다른 기기 로그인 흐름 모두에서 안전합니다

---

#### `getsessioncode` - Get Session Code

저장된 세션 코드를 가져옵니다.

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

키쌍을 생성하고 사용자 별칭(alias)에 서명합니다. 회원가입 시 사용됩니다. 회원가입이 실패했을 때 고아 키가 남지 않도록 **대기 저장소(pending storage)**를 사용합니다.

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
1. 기기가 이미 등록되어 있는지 확인합니다 (키쌍 + 세션 코드 존재 여부)
2. 새 RSA-2048 키쌍을 생성합니다
3. 키쌍을 **대기 저장소**에 저장합니다 (아직 영구 저장 아님)
4. 대기 중인 개인키로 별칭에 서명합니다 (RSA PKCS#1 v1.5 with SHA-256)
5. 서명과 대기 중인 공개키를 반환합니다

**Notes:**
- 키쌍은 대기 저장소에 저장되며, `savesessioncode`에 의해 영구 저장소로 승격됩니다
- 회원가입이 실패하면 (예: 409 Conflict) 재시도 시 대기 중인 키쌍을 안전하게 덮어쓸 수 있습니다
- 이를 통해 회원가입 실패 시 OS 키스토어에 고아 키쌍이 남는 것을 방지합니다

---

### Login Flow

#### `signaliaswithtimestamp` - Sign Alias with Timestamp

현재 타임스탬프와 함께 사용자 별칭에 서명합니다. 로그인 인증에 사용됩니다.

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
1. 현재 Unix 타임스탬프를 생성합니다
2. 페이로드를 만듭니다: `"alias:timestamp"`
3. 헬퍼의 개인키로 페이로드에 서명합니다
4. 서명과 타임스탬프를 반환합니다

---

#### `signchallengetoken` - Sign Challenge Token

챌린지 토큰을 검증하고 서명합니다. 로그인 검증에 사용됩니다.

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
1. 서버 공개키로 챌린지 토큰에 대한 서버 서명을 검증합니다
2. 헬퍼의 개인키로 챌린지 토큰에 서명합니다
3. 헬퍼의 서명을 반환합니다

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
- 대기 중인 키는 영구 저장소로 승격된 뒤 자동으로 삭제됩니다
- 대기 중인 키는 회원가입 실패 시 (예: 409 Conflict 오류) 고아 키가 남는 것을 방지합니다

## Test Mode (KEEPER_E2E_MODE)

사용자의 실제 OS Keychain을 건드리지 않고 회원가입/로그인 전체 흐름을 검증해야
하는 종단간 테스트를 위해, Keeper 프로세스를 실행하는 환경에서
`KEEPER_E2E_MODE=1`을 설정합니다. 이 모드가 활성화되면 다음과 같이 동작합니다.

- `main.init()`이 `github.com/zalando/go-keyring`의 `keyring.MockInit()`을 호출합니다
- 모든 `keyring.Set/Get/Delete` 연산이 프로세스 로컬 인메모리 맵으로 향합니다
- `EnsureServerPublicKey`가 하드코딩된 서버 공개키를 mock에 기록합니다
- OS Keychain은 읽거나 쓰지 않습니다
- 프로세스가 종료되면 모든 키가 지워집니다 (완벽한 테스트 격리)

시작 시 stderr에 `KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)`
를 기록하므로, 운영 환경에서 실수로 활성화된 경우 쉽게 찾아낼 수 있습니다.

**운영 빌드에는 영향을 주지 않습니다.** 이 환경 변수는 런타임에 확인되므로 동일한
바이너리가 두 모드 모두에서 동작합니다. Phase 12e Step 6 자동화에서 사용됩니다
([dragpass/tests/e2e-extension/keeper/](https://github.com/dragpass/dragpass/tree/develop/dragpass/tests/e2e-extension/keeper)).

### KEEPER_E2E_KEYRING_FILE (multi-process keyring sharing)

`KEEPER_E2E_MODE=1`만 설정하면 프로세스 로컬 인메모리 맵을 사용합니다. 확장의
popup과 서비스 워커(SW)가 각각 `connectNative`로 자신만의 Keeper 프로세스를
띄우면 서로 다른 mock 키링을 갖게 됩니다. 회원가입이 popup의 Keeper에는 키쌍을
저장하지만, SW의 Keeper는 빈 키링을 보게 되어 "secret not found"로
ADMIN_CREATE_ORG에 실패합니다.

`KEEPER_E2E_MODE=1`에 *더해서* `KEEPER_E2E_KEYRING_FILE=/path/to/keyring.json`을
설정하면 `storage.go`가 모든 Set/Get/Delete를 JSON 파일
(`internal/keystore/krfile.go`)에 미러링합니다. 이제 같은 파일 경로를 공유하는
모든 Keeper 프로세스가 동일한 키링 항목을 보게 됩니다. 파일은 시작 시 mock 맵에
로드되고, Set/Delete가 일어날 때마다 다시 기록됩니다.

이 플래그는 opt-in 방식이며 mock 프로바이더가 활성화된 경우에만 의미가 있습니다.
운영 빌드에서 파일 저장을 활성화하지는 않습니다. 자동화 픽스처는
`user-data-dir/e2e-keyring.json` 아래에 테스트별 경로를 생성하므로 각 테스트
실행이 서로 격리됩니다.

## Production Clipboard Smoke (DRAGPASS_KEEPER_CLIPBOARD_E2E)

`internal/keystore/clipboard`에는 실제 OS 클립보드 백엔드
(`golang.design/x/clipboard`)를 검증하는 opt-in smoke/e2e 스위트가 포함되어
있습니다. 기본적으로 **비활성화**되어 있으므로 `go test ./...`는 개발자의
클립보드를 절대 건드리지 않습니다.

실행 방법:

```bash
make test-clipboard-e2e
# equivalent to:
DRAGPASS_KEEPER_CLIPBOARD_E2E=1 \
  go test ./internal/keystore/clipboard -count=1 -run ProductionSmoke -v
```

검증 항목:

- `OSClipboard.Write`가 실제로 sentinel 문자열을 OS 클립보드에 올리는지
- TTL 만료가 sentinel을 지우는지 (best-effort, `compare-then-clear`)
- TTL 만료가 TTL 구간 동안 사용자가 복사한 값을 덮어쓰지 **않는지**. `production.go`의
  SHA-256 compare-and-clear 불변식입니다

테스트 종료 시 정리 단계에서 테스트 시작 시점에 읽어둔 클립보드 내용을 복원하므로,
정상적으로 실행되면 시스템 클립보드가 그대로 유지됩니다. 이 스위트는 기본 테스트
잡이 아니라 OS별 로컬 점검과 OS별 CI smoke 잡을 위한 것입니다.
