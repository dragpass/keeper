package localrpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

func passwordWrap(t *testing.T, password string, dek []byte) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x11}, handlers.DekSaltLength)
	kek := pbkdf2.Key([]byte(password), salt, handlers.DekPBKDF2Iterations, handlers.DekKEKLength, sha256.New)
	iv, ciphertext, err := handlers.AESGCMSealSplit(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(append(salt, iv...), ciphertext...))
}

func openPasswordWrap(t *testing.T, password, wrappedB64 string) ([]byte, error) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		t.Fatal(err)
	}
	salt := raw[:handlers.DekSaltLength]
	iv := raw[handlers.DekSaltLength : handlers.DekSaltLength+12]
	kek := pbkdf2.Key([]byte(password), salt, handlers.DekPBKDF2Iterations, handlers.DekKEKLength, sha256.New)
	return handlers.AESGCMOpen(kek, iv, raw[handlers.DekSaltLength+12:])
}

// The route answers the same DEK under the new password and nothing else:
// the device-wrapped DEK it went through stays in Keeper.
func TestAppPasswordRewrapAnswersOnlyTheNewPasswordWrap(t *testing.T) {
	server := newTestServer(t)
	if err := keychain.SaveDeviceKey(server.app.Store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))); err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x22}, 32)
	current := passwordWrap(t, "current-password", dek)
	session, csrf := openTestSession(t, server)

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/password/rewrap", map[string]string{
		"password": "current-password", "encrypted_dek_b64": current, "new_password": "new-password",
	})
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rewrap: %d %s", code, body)
	}
	var data map[string]string
	if err := remarshal(result.Data, &data); err != nil || len(data) != 1 {
		t.Fatalf("rewrap answered more than the new wrap: %s", result.Data)
	}
	stored, err := keychain.GetPersonalDeviceWrappedDEK(server.app.Store)
	if err != nil || stored == "" || bytes.Contains([]byte(body), []byte(stored)) {
		t.Fatalf("device-wrapped DEK left Keeper or was not kept: %s", body)
	}
	opened, err := openPasswordWrap(t, "new-password", data["encrypted_dek_b64"])
	if err != nil || !bytes.Equal(opened, dek) {
		t.Fatalf("the new wrap does not open to the same DEK under the new password: %v", err)
	}
	if _, err := openPasswordWrap(t, "current-password", data["encrypted_dek_b64"]); err == nil {
		t.Fatal("the new wrap still opens under the current password")
	}
}

func TestAppPasswordRewrapRefusesAWrongCurrentPassword(t *testing.T) {
	server := newTestServer(t)
	current := passwordWrap(t, "current-password", bytes.Repeat([]byte{0x22}, 32))
	session, csrf := openTestSession(t, server)

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/password/rewrap", map[string]string{
		"password": "wrong-password", "encrypted_dek_b64": current, "new_password": "new-password",
	})
	if code != http.StatusOK || result.Success || result.ErrorCode != "crypto_failure" {
		t.Fatalf("wrong current password: %d %s", code, body)
	}
	// A refused password mints no device key and stores no wrap.
	if stored, _ := keychain.GetPersonalDeviceWrappedDEK(server.app.Store); stored != "" {
		t.Fatal("a refused password stored a device-wrapped DEK")
	}
}

func TestAppPasswordRewrapDecodesStrictly(t *testing.T) {
	server := newTestServer(t)
	current := passwordWrap(t, "current-password", bytes.Repeat([]byte{0x22}, 32))
	session, csrf := openTestSession(t, server)
	for name, bad := range map[string]map[string]string{
		"unknown field":    {"password": "current-password", "encrypted_dek_b64": current, "new_password": "n", "device_wrapped_dek_b64": "AA=="},
		"no new password":  {"password": "current-password", "encrypted_dek_b64": current},
		"empty new":        {"password": "current-password", "encrypted_dek_b64": current, "new_password": ""},
		"no password wrap": {"password": "current-password", "new_password": "n"},
	} {
		code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/password/rewrap", bad)
		if code == http.StatusOK && result.Success {
			t.Fatalf("%s: accepted", name)
		}
	}
	if code, _, _ := callRoute(t, server, session, "wrong", "/v1/auth/password/rewrap", map[string]string{
		"password": "current-password", "encrypted_dek_b64": current, "new_password": "new-password",
	}); code != http.StatusForbidden {
		t.Fatalf("without the session CSRF: %d", code)
	}
}
