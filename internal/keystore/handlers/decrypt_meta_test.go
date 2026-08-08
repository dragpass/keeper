package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestDEKUnwrapAndDecryptMeta_Roundtrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(i)
	}
	deviceWrappedDEK := signupAndGetDeviceWrap(t, deps, store, "p", deviceKey)

	encDekRaw, _ := base64.StdEncoding.DecodeString(deviceWrappedDEK)
	if len(encDekRaw) <= 12 {
		t.Fatalf("wrapped dek too short")
	}
	rawDEK, err := AESGCMOpen(deviceKey, encDekRaw[:12], encDekRaw[12:])
	if err != nil {
		t.Fatalf("unwrap dek: %v", err)
	}

	const label = "personal-label"
	const targetURL = "https://personal.example.com"
	encLabel, _ := AESGCMSeal(rawDEK, []byte(label))
	encURL, _ := AESGCMSeal(rawDEK, []byte(targetURL))

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
	if data.Fields["label"] != label {
		t.Errorf("label: got %q", data.Fields["label"])
	}
	if data.Fields["target_url"] != targetURL {
		t.Errorf("target_url: got %q", data.Fields["target_url"])
	}

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
		{"empty meta_fields", proto.DEKUnwrapAndDecryptMetaRequest{EncryptedDEKB64: deviceWrappedDEK}},
		{"invalid encrypted_dek", proto.DEKUnwrapAndDecryptMetaRequest{
			EncryptedDEKB64: "!@#",
			MetaFields:      map[string]string{"l": "AAAAAAAAAAAAAAAA"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if resp := HandleDEKUnwrapAndDecryptMeta(deps, tc.req); resp.Success {
				t.Errorf("expected failure")
			}
		})
	}
}

var _ = keychain.MemorySecretStore{}
