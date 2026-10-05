// personal_dek_slot_test.go — personal dek_* actions with encrypted_dek_b64
// left empty open the device-wrapped DEK in Keeper's own slot (0.0.58).
package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestPersonalDEKActions_EmptyEncryptedDEKUsesSlot(t *testing.T) {
	deps, mc := withMemoryClipboard(t)
	store := deps.Store
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(0x40 + i)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	if resp := signupDEKForTest(deps, "pw"); !resp.Success {
		t.Fatalf("signup setup: %s", resp.Error)
	}

	const sentinel = "SLOT_DEK_SENTINEL"
	enc := HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(sentinel)),
	})
	if !enc.Success {
		t.Fatalf("encrypt from slot: %s", enc.Error)
	}
	encData := enc.Data.(proto.DEKUnwrapAndEncryptResponseData)

	copied := HandleDEKUnwrapAndDecryptToClipboard(deps, proto.DEKUnwrapAndDecryptToClipboardRequest{
		IVB64:          encData.IVB64,
		CiphertextB64:  encData.CiphertextB64,
		ClipboardTTLMs: 10_000,
	})
	if !copied.Success {
		t.Fatalf("decrypt to clipboard from slot: %s", copied.Error)
	}
	if _, has := mc.LastHash(); !has {
		t.Fatal("clipboard was not written")
	}

	iv, _ := base64.StdEncoding.DecodeString(encData.IVB64)
	ct, _ := base64.StdEncoding.DecodeString(encData.CiphertextB64)
	meta := HandleDEKUnwrapAndDecryptMeta(deps, proto.DEKUnwrapAndDecryptMetaRequest{
		MetaFields: map[string]string{"title": base64.StdEncoding.EncodeToString(append(iv, ct...))},
	})
	if !meta.Success {
		t.Fatalf("decrypt meta from slot: %s", meta.Error)
	}
	if got := meta.Data.(proto.DEKUnwrapAndDecryptMetaResponseData).Fields["title"]; got != sentinel {
		t.Fatalf("meta from slot = %q", got)
	}

	before, _ := keychain.GetPersonalDeviceWrappedDEK(store)
	aad := HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(sentinel)),
		AADB64:       base64.StdEncoding.EncodeToString([]byte("ctx")),
	})
	if !aad.Success {
		t.Fatalf("encrypt with aad from slot: %s", aad.Error)
	}
	if after, _ := keychain.GetPersonalDeviceWrappedDEK(store); after != before {
		t.Fatal("a slot-sourced call must not rewrite the slot")
	}

	rotated := HandleDEKRotateToNewPassword(deps, proto.DEKRotateToNewPasswordRequest{NewPassword: "new-pw"})
	if !rotated.Success {
		t.Fatalf("rotate to new password from slot: %s", rotated.Error)
	}
}

func TestPersonalDEKActions_EmptyEncryptedDEKWithoutSlotIsNotFound(t *testing.T) {
	deps, _ := withMemoryClipboard(t)
	setKeychainDeviceKey(t, deps.Store, make([]byte, 32))
	pt := base64.StdEncoding.EncodeToString([]byte("x"))
	iv := base64.StdEncoding.EncodeToString(make([]byte, 12))

	cases := map[string]proto.BaseResponse{
		"encrypt":     HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{PlaintextB64: pt}),
		"encrypt_aad": HandleDEKUnwrapAndEncryptWithAAD(deps, proto.DEKUnwrapAndEncryptWithAADRequest{PlaintextB64: pt, AADB64: pt}),
		"meta":        HandleDEKUnwrapAndDecryptMeta(deps, proto.DEKUnwrapAndDecryptMetaRequest{MetaFields: map[string]string{"a": ""}}),
		"clipboard": HandleDEKUnwrapAndDecryptToClipboard(deps, proto.DEKUnwrapAndDecryptToClipboardRequest{
			IVB64: iv, CiphertextB64: pt, ClipboardTTLMs: 10_000,
		}),
		"new_password": HandleDEKRotateToNewPassword(deps, proto.DEKRotateToNewPasswordRequest{NewPassword: "p"}),
	}
	for name, resp := range cases {
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
			t.Errorf("%s: want not_found, got success=%v code=%s", name, resp.Success, resp.ErrorCode)
		}
	}
}

// After device_signout removes the device master, the slot path refuses.
func TestPersonalDEKActions_SlotGoneAfterSignout(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, make([]byte, 32))
	if resp := signupDEKForTest(deps, "pw"); !resp.Success {
		t.Fatalf("signup setup: %s", resp.Error)
	}
	if resp := HandleDeviceSignout(deps, proto.DeviceSignoutRequest{}); !resp.Success {
		t.Fatalf("signout: %s", resp.Error)
	}
	resp := HandleDEKUnwrapAndEncrypt(deps, proto.DEKUnwrapAndEncryptRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("want not_found after the slot is gone, got %+v", resp)
	}
}
