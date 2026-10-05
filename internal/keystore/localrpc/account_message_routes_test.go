package localrpc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	routeGroup = "33333333-3333-4333-8333-333333333333"
)

func newKeyedRouteServer(t *testing.T) (*Server, *testdouble.MemorySecretStore, string, string, string) {
	t.Helper()
	server := newTestServer(t)
	server.app.ServerKeyVerifier = testdouble.AlwaysOKVerifier{}
	store := server.app.Store.(*testdouble.MemorySecretStore)
	own := routeKeypair(t)
	_ = keychain.SavePrivateKey(store, own.PrivateKey)
	_ = keychain.SavePublicKey(store, own.PublicKey)
	session, csrf := openTestSession(t, server)
	return server, store, own.PublicKey, session, csrf
}

func gcmSeal(t *testing.T, key, plaintext, aad []byte) (iv, ciphertext []byte) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv = bytes.Repeat([]byte{7}, gcm.NonceSize())
	return iv, gcm.Seal(nil, iv, plaintext, aad)
}

func gcmOpen(t *testing.T, key, iv, ciphertext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		t.Fatalf("does not open: %v", err)
	}
	return opened
}

func decodeData[T any](t *testing.T, result routeResult) T {
	t.Helper()
	var data T
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// The rotation's rewrap goes to the pending key Keeper staged, never to a key
// the App names, and there is nothing to rewrap to once the rotation is gone.
func TestAppAccountKeyRotationRewrapsOnlyToThePendingKey(t *testing.T) {
	server, store, own, session, csrf := newKeyedRouteServer(t)
	groupDEK := bytes.Repeat([]byte{0x51}, 32)
	wrapped := wrapTo(t, own, groupDEK)
	rewrap := map[string]string{"wrapped_for_me_b64": wrapped}

	code, status, body := callRoute(t, server, session, csrf, "/v1/account-key/rotate/status", map[string]any{})
	if code != http.StatusOK || !status.Success || decodeData[proto.RotateUserKeypairStatusResponseData](t, status).HasPending {
		t.Fatalf("status: %d %s", code, body)
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/account-key/rotate/rewrap-group-dek", rewrap); code != http.StatusBadRequest {
		t.Fatalf("rewrap without a pending key: %d", code)
	}

	code, prepared, body := callRoute(t, server, session, csrf, "/v1/account-key/rotate/prepare", map[string]any{
		"challenge_token": "server-challenge", "server_signature": "server-signature", "server_key_version": 1,
		"account_id": routeOwner, "reason": "voluntary", "rotated_at": time.Now().Unix(),
	})
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("prepare: %d %s", code, body)
	}
	newKey := decodeData[proto.RotateUserKeypairPrepareResponseData](t, prepared).NewPublicKey
	if pending, _ := keychain.GetPendingPublicKey(store); pending != newKey {
		t.Fatal("prepare did not stage the key it answered")
	}

	if code, _, _ := callRoute(t, server, session, csrf, "/v1/account-key/rotate/rewrap-group-dek",
		map[string]string{"wrapped_for_me_b64": wrapped, "other_public_key": own}); code != http.StatusBadRequest {
		t.Fatalf("rewrap took a caller key: %d", code)
	}
	code, result, body := callRoute(t, server, session, csrf, "/v1/account-key/rotate/rewrap-group-dek", rewrap)
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rewrap: %d %s", code, body)
	}
	pendingPrivate, _ := keychain.GetPendingPrivateKey(store)
	rewrapped := decodeData[struct {
		EncryptedForOtherB64 string `json:"encrypted_for_other_b64"`
	}](t, result).EncryptedForOtherB64
	if !bytes.Equal(openWith(t, pendingPrivate, rewrapped), groupDEK) {
		t.Fatal("rewrap did not reach the pending key")
	}

	if code, aborted, body := callRoute(t, server, session, csrf, "/v1/account-key/rotate/abort", map[string]any{}); code != http.StatusOK || !aborted.Success {
		t.Fatalf("abort: %d %s", code, body)
	}
	if active, _ := keychain.GetPublicKey(store); active != own {
		t.Fatal("abort touched the active key")
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/account-key/rotate/rewrap-group-dek", rewrap); code != http.StatusBadRequest {
		t.Fatalf("rewrap after abort: %d", code)
	}
}

func TestAppDeviceForgetDeletesTheDeviceKeyOnce(t *testing.T) {
	server, store, _, session, csrf := newKeyedRouteServer(t)
	_ = keychain.SaveDeviceKey(store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/device/forget", map[string]any{"scope": "all"}); code != http.StatusBadRequest {
		t.Fatalf("forget took a field: %d", code)
	}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/device/forget", map[string]any{}); code != http.StatusOK || !result.Success || string(result.Data) != `{"forgotten":true}` {
		t.Fatalf("forget: %d %s", code, body)
	}
	// A retry after the server revocation failed finds nothing to delete.
	if code, result, body := callRoute(t, server, session, csrf, "/v1/device/forget", map[string]any{}); code != http.StatusOK || !result.Success || string(result.Data) != `{"forgotten":false}` {
		t.Fatalf("forget again: %d %s", code, body)
	}
	if present, _ := keychain.DeviceKeyPresent(store); present {
		t.Fatal("the device key is still there")
	}
	if active, _ := keychain.GetPublicKey(store); active == "" {
		t.Fatal("forget removed the account key")
	}
}

func openRouteHandle(t *testing.T, server *Server, session, csrf, own string, groupDEK []byte) string {
	t.Helper()
	code, opened, body := callRoute(t, server, session, csrf, "/v1/group-dek/open",
		map[string]string{"encrypted_group_dek": wrapTo(t, own, groupDEK)})
	if code != http.StatusOK || !opened.Success {
		t.Fatalf("open: %d %s", code, body)
	}
	return decodeData[proto.GroupSessionOpenResponseData](t, opened).GroupHandle
}

// A message sealed through the route opens only under the message AAD, and
// the display pair returns it under a permit for the challenge Keeper minted.
func TestAppSecureMessageRoutesSealUnderTheMessageAADAndDisplayUnderAPermit(t *testing.T) {
	server, _, own, session, csrf := newKeyedRouteServer(t)
	groupDEK := bytes.Repeat([]byte{0x61}, 32)
	handle := openRouteHandle(t, server, session, csrf, own, groupDEK)
	expiry := time.Now().Add(time.Hour).Unix()
	const secret = "meet at noon"
	seal := map[string]any{
		"group_handle": handle, "org_id": routeOwner, "group_id": routeGroup, "dek_version": 3,
		"token_expires_at": expiry, "plaintext_b64": base64.StdEncoding.EncodeToString([]byte(secret)),
	}

	code, sealed, body := callRoute(t, server, session, csrf, "/v1/message/seal", seal)
	if code != http.StatusOK || !sealed.Success || strings.Contains(body, secret) {
		t.Fatalf("seal: %d %s", code, body)
	}
	out := decodeData[proto.GroupEncryptResponseData](t, sealed)
	iv, _ := base64.StdEncoding.DecodeString(out.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(out.CiphertextB64)
	aad := proto.MessageAADCanonical(routeOwner, routeGroup, 3, proto.MessageSchemaVersion, expiry)
	if string(gcmOpen(t, groupDEK, iv, ciphertext, []byte(aad))) != secret {
		t.Fatal("the seal is not under the message AAD")
	}

	refusals := map[string]func(map[string]any){
		"a caller AAD": func(m map[string]any) {
			m["aad_b64"] = base64.StdEncoding.EncodeToString([]byte("dragpass.credential"))
		},
		"a malformed org":  func(m map[string]any) { m["org_id"] = "org-1" },
		"no expiry":        func(m map[string]any) { m["token_expires_at"] = 0 },
		"an empty message": func(m map[string]any) { m["plaintext_b64"] = "" },
		"an oversized text": func(m map[string]any) {
			m["plaintext_b64"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 513))
		},
	}
	for name, mutate := range refusals {
		changed := map[string]any{}
		for key, value := range seal {
			changed[key] = value
		}
		mutate(changed)
		if code, _, _ := callRoute(t, server, session, csrf, "/v1/message/seal", changed); code != http.StatusBadRequest {
			t.Fatalf("seal with %s: %d", name, code)
		}
	}

	input := map[string]any{
		"group_handle": handle, "org_id": routeOwner, "group_id": routeGroup, "dek_version": 3,
		"message_schema_version": 1, "token_expires_at": expiry, "audit_table_id": nil,
		"iv_b64": out.IVB64, "ciphertext_b64": out.CiphertextB64,
	}
	code, prepared, body := callRoute(t, server, session, csrf, "/v1/message/display-prepare", input)
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("prepare: %d %s", code, body)
	}
	challenge := decodeData[proto.MessageDisplayPrepareResponseData](t, prepared).Challenge
	digest := sha256.Sum256(append(append([]byte{}, iv...), ciphertext...))
	now := time.Now().Unix()
	display := map[string]any{}
	for key, value := range input {
		display[key] = value
	}
	display["permit"] = map[string]any{
		"challenge": challenge, "group_id": routeGroup, "dek_version": 3, "message_schema_version": 1,
		"token_expires_at": expiry, "audit_table_id": nil, "payload_sha256": hex.EncodeToString(digest[:]),
		"account_id": routePeer, "org_id": routeOwner, "issued_at": now, "expires_at": now + 30,
		"server_key_version": 1, "signature": base64.StdEncoding.EncodeToString([]byte("signed")),
	}
	code, shown, body := callRoute(t, server, session, csrf, "/v1/message/display", display)
	if code != http.StatusOK || !shown.Success {
		t.Fatalf("display: %d %s", code, body)
	}
	plaintext, _ := base64.StdEncoding.DecodeString(decodeData[proto.GroupDecryptWithAadForAppDisplayResponseData](t, shown).PlaintextB64)
	if string(plaintext) != secret {
		t.Fatal("display did not return the message")
	}
	if code, again, _ := callRoute(t, server, session, csrf, "/v1/message/display", display); code != http.StatusOK || again.Success {
		t.Fatalf("a consumed challenge displayed again: %d", code)
	}
}

// A drag token re-encrypts to the guest format without its plaintext in any
// answer; the guest key opens it.
func TestAppGuestShareTranscryptReturnsOnlyTheGuestCiphertextAndKey(t *testing.T) {
	server, _, own, session, csrf := newKeyedRouteServer(t)
	groupDEK := bytes.Repeat([]byte{0x71}, 32)
	handle := openRouteHandle(t, server, session, csrf, own, groupDEK)
	const secret = "the vault code"
	iv, ciphertext := gcmSeal(t, groupDEK, []byte(secret), nil)
	salt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
	request := map[string]any{
		"group_handle": handle, "iv_b64": base64.StdEncoding.EncodeToString(iv),
		"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext),
	}

	code, result, body := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", request)
	if code != http.StatusOK || !result.Success || strings.Contains(body, secret) {
		t.Fatalf("transcrypt: %d %s", code, body)
	}
	out := decodeData[proto.GroupTranscryptForGuestResponseData](t, result)
	key, _ := base64.RawURLEncoding.DecodeString(out.GuestKey)
	guest, _ := base64.StdEncoding.DecodeString(out.GuestCiphertext)
	if string(gcmOpen(t, key, guest[:12], guest[12:], nil)) != secret {
		t.Fatal("the guest key does not open the guest ciphertext")
	}

	request["passphrase"] = "correct horse"
	if code, refused, _ := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", request); code != http.StatusOK || refused.Success {
		t.Fatalf("a passphrase without its salt: %d", code)
	}
	request["passphrase_salt"] = salt
	code, result, body = callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", request)
	if code != http.StatusOK || !result.Success || strings.Contains(body, "correct horse") {
		t.Fatalf("passphrase transcrypt: %d %s", code, body)
	}

	// A message token is AAD-bound, so the non-AAD transcrypt cannot open it.
	messageIV, messageCiphertext := gcmSeal(t, groupDEK, []byte(secret), []byte("dragpass.message|1"))
	request = map[string]any{
		"group_handle": handle, "iv_b64": base64.StdEncoding.EncodeToString(messageIV),
		"ciphertext_b64": base64.StdEncoding.EncodeToString(messageCiphertext),
	}
	if code, refused, body := callRoute(t, server, session, csrf, "/v1/guest-share/transcrypt", request); code != http.StatusOK || refused.Success || strings.Contains(body, secret) {
		t.Fatalf("an AAD-bound ciphertext transcrypted: %d %s", code, body)
	}
}
