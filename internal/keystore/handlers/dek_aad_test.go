// dek_aad_test.go — personal-scope AAD-binding encrypt regression guards.
//
// The point of the action is the binding: a personal sealed credential payload
// must not open under a different canonical context. These mirror the group
// variant's guards (group_encrypt_aad_test.go) so the two scopes are held to
// the same contract.

package handlers

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// sealPersonalWithAAD seeds a device key, wraps a fresh DEK to it, and returns
// the device-wrapped DEK plus the raw DEK for out-of-band verification.
func sealPersonalWithAAD(t *testing.T) (deps Deps, encryptedDEKB64 string, dek []byte) {
	t.Helper()
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x20 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)

	resp := HandleDEKGenerateAndWrapDual(deps, proto.DEKGenerateAndWrapDualRequest{
		Password: "testpass-aad",
	})
	if !resp.Success {
		t.Fatalf("dual wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKGenerateAndWrapDualResponseData)

	devRaw, err := base64.StdEncoding.DecodeString(data.DeviceWrappedDEKB64)
	if err != nil {
		t.Fatalf("decode device wrap: %v", err)
	}
	raw, err := AESGCMOpen(deviceKey, devRaw[:12], devRaw[12:])
	if err != nil {
		t.Fatalf("device decrypt: %v", err)
	}
	return deps, data.DeviceWrappedDEKB64, raw
}

func TestHandleDEKUnwrapAndEncryptWithAAD_RoundTrip(t *testing.T) {
	deps, encryptedDEKB64, dek := sealPersonalWithAAD(t)

	const sentinel = "PERSONAL_AAD_PLAINTEXT_SENTINEL"
	// Canonical AAD, personal scope: account_id replaces org_id.
	aad := []byte("acct_42|entry_7|credential|1|1")

	resp := HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{
		EncryptedDEKB64: encryptedDEKB64,
		PlaintextB64:    base64.StdEncoding.EncodeToString([]byte(sentinel)),
		AADB64:          base64.StdEncoding.EncodeToString(aad),
	})
	if !resp.Success {
		t.Fatalf("seal failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKUnwrapAndEncryptResponseData)

	iv, err := base64.StdEncoding.DecodeString(data.IVB64)
	if err != nil {
		t.Fatalf("decode iv: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(data.CiphertextB64)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	// Opens only under the byte-identical AAD.
	pt, err := AESGCMOpenWithAAD(dek, iv, ct, aad)
	if err != nil {
		t.Fatalf("open with same aad: %v", err)
	}
	if string(pt) != sentinel {
		t.Errorf("plaintext = %q, want %q", pt, sentinel)
	}

	// The plaintext must not appear anywhere in the response.
	if strings.Contains(data.IVB64+data.CiphertextB64, sentinel) {
		t.Error("plaintext sentinel echoed in response")
	}
}

func TestHandleDEKUnwrapAndEncryptWithAAD_SwapAADFails(t *testing.T) {
	deps, encryptedDEKB64, dek := sealPersonalWithAAD(t)

	sealAAD := []byte("acct_42|entry_7|credential|1|1")
	resp := HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{
		EncryptedDEKB64: encryptedDEKB64,
		PlaintextB64:    base64.StdEncoding.EncodeToString([]byte("secret payload")),
		AADB64:          base64.StdEncoding.EncodeToString(sealAAD),
	})
	if !resp.Success {
		t.Fatalf("seal failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKUnwrapAndEncryptResponseData)
	iv, _ := base64.StdEncoding.DecodeString(data.IVB64)
	ct, _ := base64.StdEncoding.DecodeString(data.CiphertextB64)

	// A different entry in the same account must not open it — this is the
	// swap guard the whole action exists for.
	otherAAD := []byte("acct_42|entry_8|credential|1|1")
	if _, err := AESGCMOpenWithAAD(dek, iv, ct, otherAAD); err == nil {
		t.Error("payload opened under a different AAD — swap guard is not binding")
	}
	// So must a different account holding the same entry id.
	otherAccount := []byte("acct_43|entry_7|credential|1|1")
	if _, err := AESGCMOpenWithAAD(dek, iv, ct, otherAccount); err == nil {
		t.Error("payload opened under a different account AAD")
	}
}

func TestHandleDEKUnwrapAndEncryptWithAAD_RequiresAAD(t *testing.T) {
	deps, encryptedDEKB64, _ := sealPersonalWithAAD(t)

	// Empty AAD is what the plain DEKUnwrapAndEncrypt action covers; this one
	// exists to bind, so it must refuse rather than silently seal unbound.
	resp := HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{
		EncryptedDEKB64: encryptedDEKB64,
		PlaintextB64:    base64.StdEncoding.EncodeToString([]byte("x")),
		AADB64:          "",
	})
	if resp.Success {
		t.Error("empty aad_b64 accepted — the action must require a bound AAD")
	}
}
