# DragPass Keeper

[DragPass Chrome Extension](https://chromewebstore.google.com/detail/blindfold/cmgjlocmnppfpknaipdfodjhbplnhimk?hl=ko&utm_source=ext_sidebar)（**v1.0.2**）向けの、オープンソースなネイティブ鍵カストディ用ヘルパーです。RSA / AES の暗号処理を実行し、秘密鍵のマテリアルを保持することで、鍵がブラウザに一切入らないようにします。これが DragPass のエンドツーエンド暗号化を検証可能にしている仕組みです。

<sub>[English](README.md) | [한국어](README.ko.md) | 日本語</sub>

ライセンスは [Apache-2.0](LICENSE) です。

このヘルパーは、デバイス鍵を OS ネイティブの暗号化ボールトに安全に保管します。

- **macOS**: Keychain
- **Linux**: Secret Service API（GNOME Keyring / KDE Wallet）
- **Windows**: Credential Manager

## ダウンロード

最新リリースは [Releases ページ](https://github.com/dragpass/keeper/releases) からダウンロードしてください。

### 提供パッケージ

- **macOS**:
  - `dragpass-keeper-macos-x86_64.pkg`（Intel）
  - `dragpass-keeper-macos-arm64.pkg`（Apple Silicon）
- **Linux**:
  - `dragpass-keeper-linux-x86_64.deb`（x86_64/amd64）
  - `dragpass-keeper-linux-arm64.deb`（ARM64）
- **Windows**: `dragpass-keeper.exe`（x64 インストーラー）

## ダウンロードの検証

すべてのリリースパッケージは、セキュリティのため GPG で署名されています。ダウンロードしたファイルの完全性を検証することを強く推奨します。

### 1. 公開鍵のインポート

```bash
# Download and import the public key
curl https://raw.githubusercontent.com/dragpass/keeper/main/GPG_PUBLIC_KEY.asc | gpg --import
```

または [GPG_PUBLIC_KEY.asc](GPG_PUBLIC_KEY.asc) から手動でインポートしてください。

**鍵のフィンガープリント**: `66DF 4017 8A5F 6F66 EAAF 318A 3FC4 1856 9192 8FDC`

### 2. 署名の検証

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

次のような出力が表示されるはずです。
```
gpg: Good signature from "JinHyeok Hong <vjinhyeokv@gmail.com>" [ultimate]
```

## インストール後に生成されるファイル

### macOS

`.pkg` ファイルをインストールすると、次のファイルが生成されます。

- `/Library/Application Support/DragPass/dragpass-keeper` - メイン実行ファイル
- `/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json` - Chrome Native Messaging マニフェスト

**鍵の保管先**: macOS Keychain

### Linux

`.deb` ファイルをインストールすると、次のファイルが生成されます。

- `/opt/dragpass/dragpass-keeper` - メイン実行ファイル
- `/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json` - Chrome マニフェスト
- `/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json` - Chromium マニフェスト

**鍵の保管先**: Secret Service API（GNOME Keyring / KDE Wallet）

### Windows

`.exe` インストーラーを実行すると、次のファイルが生成されます。

**64 ビットシステム:**
- `C:\Program Files\DragPass\`
  - `dragpass-keeper.exe` - メイン実行ファイル
  - `com.dragpass.keeper.json` - Chrome Native Messaging マニフェスト
  - `unins000.exe` - アンインストーラー
  - `unins000.dat` - アンインストーラーのデータ

**32 ビットシステム:**
- `C:\Program Files (x86)\DragPass\`
  - `dragpass-keeper.exe` - メイン実行ファイル
  - `com.dragpass.keeper.json` - Chrome Native Messaging マニフェスト
  - `unins000.exe` - アンインストーラー
  - `unins000.dat` - アンインストーラーのデータ

**鍵の保管先**: Windows Credential Manager

## API リファレンス

DragPass Keeper は Native Messaging プロトコルを介して Chrome 拡張機能と通信します。すべてのメッセージは、型安全性と拡張性を高めるために **エンベロープパターン** を採用しています。

### メッセージ形式

**リクエスト（エンベロープパターン）:**
```json
{
  "action": "action_name",
  "payload": {
    // action-specific fields
  }
}
```

**成功レスポンス:**
```json
{
  "success": true,
  "data": {
    // action-specific response data
  }
}
```

**エラーレスポンス:**
```json
{
  "success": false,
  "error": "error message"
}
```

---

### ヘルスチェック

#### `ping` - ヘルスチェック

DragPass Keeper が稼働中で応答可能かどうかを確認します。

**リクエスト:**
```json
{
  "action": "ping"
}
```

**レスポンス:**
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

### デバイス鍵の管理

#### `savedevicekey` - デバイス鍵の保存

デバイス暗号化鍵を OS のキーストアに保存します。

**リクエスト:**
```json
{
  "action": "savedevicekey",
  "payload": {
    "key": "base64_encoded_device_key"
  }
}
```

**レスポンス:**
```json
{
  "success": true
}
```

---

#### `getdevicekey` - デバイス鍵の取得

保存されているデバイス暗号化鍵を取得します。

**リクエスト:**
```json
{
  "action": "getdevicekey"
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "key": "base64_encoded_device_key"
  }
}
```

---

#### `deletedevicekey` - デバイス鍵の削除

デバイス暗号化鍵をキーストアから削除します。

**リクエスト:**
```json
{
  "action": "deletedevicekey"
}
```

**レスポンス:**
```json
{
  "success": true
}
```

---

#### `reset_device_identity` - デバイスアイデンティティのリセット

サーバー側でアカウントや DB がリセットされた後、ユーザーがこのデバイスで再登録
できるように、デバイスに残るアカウント関連の鍵素材をすべて消去します。アクティブ
鍵ペア、保留中の鍵ペア、セッションコード、デバイス鍵を削除します。
`server_public_key` はアカウントに依存しない信頼アンカーのため保持されます。冪等
であり（対象が何もなくても成功します）、鍵素材は返さず、削除したスロット名のみを
返します。

**リクエスト:**
```json
{
  "action": "reset_device_identity"
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "cleared": ["keeper_private_key", "keeper_public_key", "session_code", "device_key"]
  }
}
```

---

### 鍵ペアの管理

#### `generatekeypair` - RSA 鍵ペアの生成

ヘルパー用に新しい RSA-2048 鍵ペアを生成します。サーバー署名の検証が必要です。

**リクエスト:**
```json
{
  "action": "generatekeypair",
  "payload": {
    "challenge_token": "server_provided_challenge_token",
    "signature": "base64_server_signature"
  }
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**補足:**
- サーバーの公開鍵を使って署名を検証します
- 新しい鍵ペアを生成する前に、既存のセッションコードと鍵ペアを削除します
- 秘密鍵と公開鍵の両方を OS のキーストアに保存します

---

#### `getpublickey` - ヘルパー公開鍵の取得

ヘルパーの公開鍵を取得します。

**リクエスト:**
```json
{
  "action": "getpublickey"
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

---

#### `getserverpubkey` - サーバー公開鍵の取得

OS のキーストアに保存されているサーバーの公開鍵を取得します。

**リクエスト:**
```json
{
  "action": "getserverpubkey"
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**補足:**
- サーバー公開鍵はバイナリにハードコードされており、初回起動時に初期化されます
- この鍵はサーバーからの署名を検証するために使用されます
- 取得できるよう OS ネイティブのキーストアに保存されます

---

### セッションコードの管理

#### `savesessioncode` - 暗号化されたセッションコードの保存

保留中の鍵ペアを永続ストレージへ昇格させ、セッションコードを保存します。サインアップと別デバイスでのログインの両フローで使用されます。

**リクエスト:**
```json
{
  "action": "savesessioncode",
  "payload": {
    "encrypted_session_code": "base64_encrypted_session_code",
    "signature": "base64_server_signature"
  }
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "session_code": "decrypted_session_code"
  }
}
```

**処理内容:**
1. サーバーの公開鍵を使って署名を検証します
2. **保留中の鍵ペアを永続ストレージへ昇格させます**（サインアップで生成済みの場合）
   - サインアップフロー: 保留中の鍵ペアが存在する → 昇格
   - 別デバイスでのログインフロー: 保留中の鍵ペアがない → スキップ
3. ヘルパーの秘密鍵を使ってセッションコードを復号します（RSA-OAEP with SHA-256）
4. 復号したセッションコードを OS のキーストアに保存します
5. 復号したセッションコードを返します

**補足:**
- このアクションは、サインアップ鍵ペアのライフサイクルにおける 2 フェーズコミットを完了させます
- サインアップと別デバイスでのログインの両フローで安全に使用できます

---

#### `getsessioncode` - セッションコードの取得

保存されているセッションコードを取得します。

**リクエスト:**
```json
{
  "action": "getsessioncode"
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "session_code": "stored_session_code"
  }
}
```

---

### サインアップフロー

#### `signalias` - ユーザーエイリアスの署名

鍵ペアを生成し、ユーザーエイリアスに署名します。サインアップ時に使用されます。サインアップが失敗した場合に孤立した鍵が残らないよう、**保留ストレージ** を使用します。

**リクエスト:**
```json
{
  "action": "signalias",
  "payload": {
    "alias": "user_alias"
  }
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_signature",
    "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }
}
```

**処理内容:**
1. デバイスがすでに登録済みか（鍵ペアとセッションコードが存在するか）を確認します
2. 新しい RSA-2048 鍵ペアを生成します
3. 鍵ペアを **保留ストレージ** に保存します（まだ永続化しません）
4. 保留中の秘密鍵を使ってエイリアスに署名します（RSA PKCS#1 v1.5 with SHA-256）
5. 署名と保留中の公開鍵を返します

**補足:**
- 鍵ペアは保留ストレージに保存され、`savesessioncode` によって永続ストレージへ昇格されます
- サインアップが失敗した場合（例: 409 Conflict）、リトライ時に保留中の鍵ペアを安全に上書きできます
- これにより、サインアップ失敗時に OS のキーストアへ孤立した鍵ペアが残るのを防ぎます

---

### ログインフロー

#### `signaliaswithtimestamp` - タイムスタンプ付きエイリアス署名

現在のタイムスタンプを付けてユーザーエイリアスに署名します。ログイン認証に使用されます。

**リクエスト:**
```json
{
  "action": "signaliaswithtimestamp",
  "payload": {
    "alias": "user_alias"
  }
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_signature",
    "timestamp": 1234567890
  }
}
```

**処理内容:**
1. 現在の Unix タイムスタンプを生成します
2. ペイロード `"alias:timestamp"` を作成します
3. ヘルパーの秘密鍵を使ってペイロードに署名します
4. 署名とタイムスタンプを返します

---

#### `signchallengetoken` - チャレンジトークンの署名

チャレンジトークンを検証して署名します。ログイン検証に使用されます。

**リクエスト:**
```json
{
  "action": "signchallengetoken",
  "payload": {
    "challenge_token": "server_challenge_token",
    "signature": "base64_server_signature"
  }
}
```

**レスポンス:**
```json
{
  "success": true,
  "data": {
    "signature": "base64_helper_signature"
  }
}
```

**処理内容:**
1. サーバーの公開鍵を使って、チャレンジトークンに対するサーバーの署名を検証します
2. ヘルパーの秘密鍵を使ってチャレンジトークンに署名します
3. ヘルパーの署名を返します

---

## 暗号処理の詳細

### 鍵の形式
- **RSA 鍵長**: 2048 ビット
- **秘密鍵の形式**: PKCS#8 PEM
- **公開鍵の形式**: PKIX PEM

### アルゴリズム
- **署名アルゴリズム**: RSA PKCS#1 v1.5 with SHA-256
- **暗号化アルゴリズム**: RSA-OAEP with SHA-256
- **ハッシュ関数**: SHA-256

### 鍵の保管場所

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

**補足:**
- 保留中の鍵は、永続ストレージへの昇格後に自動的に削除されます
- 保留中の鍵は、サインアップ失敗時（例: 409 Conflict エラー）に孤立した鍵が残るのを防ぎます

## テストモード（KEEPER_E2E_MODE）

ユーザーの実際の OS Keychain に触れずにサインアップ／ログインの全フローを実行する
エンドツーエンドテストのために、Keeper プロセスを起動する環境で
`KEEPER_E2E_MODE=1` を設定してください。有効にすると次のように動作します。

- `main.init()` が `github.com/zalando/go-keyring` の `keyring.MockInit()` を呼び出します
- すべての `keyring.Set/Get/Delete` 操作は、プロセスローカルのインメモリマップへ送られます
- `EnsureServerPublicKey` はハードコードされたサーバー公開鍵をモックに書き込みます
- OS Keychain の読み書きは一切行われません
- プロセス終了時にすべての鍵がクリアされます（テストの完全な分離）

起動時に stderr へ `KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)`
とログ出力されるため、本番環境での誤った有効化を見つけやすくなっています。

**本番ビルドには影響しません** — この環境変数は実行時にチェックされるため、
同じバイナリが両方のモードで動作します。

### KEEPER_E2E_KEYRING_FILE（複数プロセス間でのキーリング共有）

`KEEPER_E2E_MODE=1` 単体では、プロセスローカルのインメモリマップが使われます。拡張機能の
popup と service worker（SW）がそれぞれ `connectNative` で独自の Keeper プロセスを
起動すると、別々のモックキーリングを持つことになります。サインアップは popup 側の
Keeper に鍵ペアを永続化しますが、SW 側の Keeper は空のキーリングしか見えず、
"secret not found" で ADMIN_CREATE_ORG に失敗します。

`KEEPER_E2E_MODE=1` に *加えて* `KEEPER_E2E_KEYRING_FILE=/path/to/keyring.json` を
設定すると、`storage.go` がすべての Set/Get/Delete を JSON ファイル
（`internal/keystore/krfile.go`）へミラーリングします。同じファイルパスを共有する
すべての Keeper プロセスが、同一のキーリングエントリを参照できるようになります。
ファイルは起動時にモックマップへ読み込まれ、Set/Delete のたびに書き戻されます。

このフラグはオプトインであり、モックプロバイダーが有効なときにのみ意味を持ちます。
本番ビルドでファイルストレージを有効にすることはありません。自動化フィクスチャは
`user-data-dir/e2e-keyring.json` の下にテストごとのパスを生成するため、テスト実行同士が
互いに分離されます。

## 本番クリップボードスモークテスト（DRAGPASS_KEEPER_CLIPBOARD_E2E）

`internal/keystore/clipboard` には、実際の OS クリップボードバックエンド
（`golang.design/x/clipboard`）を実行するオプトインのスモーク／e2e スイートが含まれています。
これは **デフォルトで無効** になっているため、`go test ./...` が開発者のクリップボードに
触れることはありません。

実行するには次のようにします。

```bash
make test-clipboard-e2e
# equivalent to:
DRAGPASS_KEEPER_CLIPBOARD_E2E=1 \
  go test ./internal/keystore/clipboard -count=1 -run ProductionSmoke -v
```

検証内容:

- `OSClipboard.Write` が実際にセンチネル文字列を OS クリップボードへ書き込むこと。
- TTL の失効によってセンチネルがクリアされること（ベストエフォート、`compare-then-clear`）。
- TTL の失効が、TTL ウィンドウ中にユーザーがコピーした値を上書きしないこと
  — `production.go` の SHA-256 による compare-and-clear 不変条件です。

クリーンアップでは、テスト開始時に読み取ったクリップボードの内容を復元するため、
クリーンな実行ではシステムのクリップボードはそのまま残ります。このスイートは
OS 固有のローカルチェックと OS ごとの CI スモークジョブを想定したものであり、
デフォルトのテストジョブではありません。
