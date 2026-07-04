// decrypt_meta_test.go — bulk meta-fields decrypt regression guard.
//
// Carve-out invariants:
//   - response envelope contains plaintext metadata (intentional — UI display)
//   - value plaintext / "secret" keyword appears 0 times (separate action)
//   - Item DEK / Group DEK / personal DEK raw bytes also 0 times in response

package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestAESUnwrapAndDecryptMeta_Roundtrip — group entry meta fields roundtrip.
func TestAESUnwrapAndDecryptMeta_Roundtrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)

	gen := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: handle})
	if !gen.Success {
		t.Fatalf("generate: %s", gen.Error)
	}
	wrapped := gen.Data.(proto.AESGenerateAndWrapResponseData).WrappedItemDEK
	itemDEKB64 := gen.Data.(proto.AESGenerateAndWrapResponseData).ItemDEKRawB64
	itemDEK, _ := base64.StdEncoding.DecodeString(itemDEKB64)

	const LABEL = "my-secret-label"
	const URL = "https://example.com/login"
	const HOSTNAME = "example.com"

	encLabel, _ := AESGCMSeal(itemDEK, []byte(LABEL))
	encURL, _ := AESGCMSeal(itemDEK, []byte(URL))
	encHostname, _ := AESGCMSeal(itemDEK, []byte(HOSTNAME))

	resp := HandleAESUnwrapAndDecryptMeta(deps, proto.AESUnwrapAndDecryptMetaRequest{
		WrappedItemDEK: wrapped,
		GroupHandle:    handle,
		MetaFields: map[string]string{
			"label":           encLabel,
			"target_url":      encURL,
			"target_hostname": encHostname,
		},
	})
	if !resp.Success {
		t.Fatalf("decrypt meta: %s", resp.Error)
	}
	data := resp.Data.(proto.AESUnwrapAndDecryptMetaResponseData)

	if data.Fields["label"] != LABEL {
		t.Errorf("label: got %q, want %q", data.Fields["label"], LABEL)
	}
	if data.Fields["target_url"] != URL {
		t.Errorf("target_url: got %q", data.Fields["target_url"])
	}
	if data.Fields["target_hostname"] != HOSTNAME {
		t.Errorf("target_hostname: got %q", data.Fields["target_hostname"])
	}

	// Regression guard: response envelope must contain forbidden fields 0
	// times (plaintext metadata is OK, but "secret" keyword or raw key bytes
	// are not).
	rawJSON, _ := json.Marshal(resp.Data)
	if strings.Contains(string(rawJSON), itemDEKB64) {
		t.Error("response envelope leaked Item DEK raw bytes")
	}
	for _, forbidden := range []string{"\"secret\"", "\"value\"", "plaintext_b64"} {
		if strings.Contains(string(rawJSON), forbidden) {
			t.Errorf("response contains forbidden field %q", forbidden)
		}
	}
}

func TestAESUnwrapAndDecryptMeta_RejectsInvalid(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)
	gen := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: handle})
	wrapped := gen.Data.(proto.AESGenerateAndWrapResponseData).WrappedItemDEK

	cases := []struct {
		name string
		req  proto.AESUnwrapAndDecryptMetaRequest
	}{
		{"empty meta_fields", proto.AESUnwrapAndDecryptMetaRequest{
			WrappedItemDEK: wrapped, GroupHandle: handle,
		}},
		{"invalid wrapped", proto.AESUnwrapAndDecryptMetaRequest{
			WrappedItemDEK: "!@#",
			GroupHandle:    handle,
			MetaFields:     map[string]string{"l": "AAAAAAAAAAAAAAAA"},
		}},
		{"meta cipher too short", proto.AESUnwrapAndDecryptMetaRequest{
			WrappedItemDEK: wrapped,
			GroupHandle:    handle,
			MetaFields:     map[string]string{"l": "AA=="}, // 1B
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleAESUnwrapAndDecryptMeta(deps, tc.req)
			if resp.Success {
				t.Errorf("expected failure")
			}
		})
	}
}

// TestDEKUnwrapAndDecryptMeta_Roundtrip — personal entry meta fields roundtrip.
func TestDEKUnwrapAndDecryptMeta_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(i)
	}
	deviceWrappedDEK := signupAndGetDeviceWrap(t, deps, store, "p", deviceKey)

	// unwrap the personal DEK once (test-only — used for meta plaintext)
	rawDEK := make([]byte, 32)
	if _, err := rand.Read(rawDEK); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Unwrapping the wrap built by signupAndGetDeviceWrap to obtain a raw
	// DEK is awkward — instead, generate a fresh raw DEK + new wrap for testing.
	encDekRaw, _ := base64.StdEncoding.DecodeString(deviceWrappedDEK)
	if len(encDekRaw) <= 12 {
		t.Fatalf("wrapped dek too short")
	}
	pt, err := AESGCMOpen(deviceKey, encDekRaw[:12], encDekRaw[12:])
	if err != nil {
		t.Fatalf("unwrap dek: %v", err)
	}
	rawDEK = pt

	const LABEL = "personal-label"
	const URL = "https://personal.example.com"
	encLabel, _ := AESGCMSeal(rawDEK, []byte(LABEL))
	encURL, _ := AESGCMSeal(rawDEK, []byte(URL))

	resp := HandleDEKUnwrapAndDecryptMeta(deps, proto.DEKUnwrapAndDecryptMetaRequest{
		EncryptedDEKB64: deviceWrappedDEK,
		MetaFields: map[string]string{
			"label":      encLabel,
			"target_url": encURL,
		},
	})
	if !resp.Success {
		t.Fatalf("decrypt meta: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKUnwrapAndDecryptMetaResponseData)
	if data.Fields["label"] != LABEL {
		t.Errorf("label: got %q", data.Fields["label"])
	}
	if data.Fields["target_url"] != URL {
		t.Errorf("target_url: got %q", data.Fields["target_url"])
	}

	// raw DEK must not be echoed in the response
	rawJSON, _ := json.Marshal(resp.Data)
	if strings.Contains(string(rawJSON), base64.StdEncoding.EncodeToString(rawDEK)) {
		t.Error("response envelope leaked DEK raw bytes")
	}
}

func TestDEKUnwrapAndDecryptMeta_RejectsInvalid(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	deviceWrappedDEK := signupAndGetDeviceWrap(t, deps, store, "p", deviceKey)

	cases := []struct {
		name string
		req  proto.DEKUnwrapAndDecryptMetaRequest
	}{
		{"empty meta_fields", proto.DEKUnwrapAndDecryptMetaRequest{
			EncryptedDEKB64: deviceWrappedDEK,
		}},
		{"invalid encrypted_dek", proto.DEKUnwrapAndDecryptMetaRequest{
			EncryptedDEKB64: "!@#",
			MetaFields:      map[string]string{"l": "AAAAAAAAAAAAAAAA"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleDEKUnwrapAndDecryptMeta(deps, tc.req)
			if resp.Success {
				t.Errorf("expected failure")
			}
		})
	}
}

// keychain.SecretStore is referenced through deps; explicit import keeps go vet happy.
var _ = keychain.MemorySecretStore{}
