// item_dek_test.go — regression guard for Item DEK handlers in item_dek.go.
//
// **Additional defects caught:**
//   - regression where HandleAESGenerateAndWrap emits a success log on the store-miss branch
package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// openSessionForFreshKey creates a fresh 32B Group DEK, registers it with
// deps's GroupSessions, and returns the (handle, raw bytes) pair. Auto-closed
// on test end.
//
// raw is wiped when the store takes it via NewBufferFromBytes, so a separate
// copy is returned to the caller — so the test can make assertions directly
// on raw bytes (e.g., unwrapItemDEK).
func openSessionForFreshKey(t *testing.T, deps Deps) (handle string, raw []byte) {
	t.Helper()
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rawCopy := make([]byte, 32)
	copy(rawCopy, raw)
	handle, _, err := deps.GroupSessions.Open(rawCopy)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		deps.GroupSessions.Close(handle)
	})
	return handle, raw
}

// TestAESGenerateAndWrap_Roundtrip: generate + wrap a new Item DEK, then
// unwrap with the same Group DEK and check the raw bytes match the response's
// ItemDEKRawB64.
func TestAESGenerateAndWrap_Roundtrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, groupRaw := openSessionForFreshKey(t, deps)

	resp := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: handle})
	if !resp.Success {
		t.Fatalf("generate_and_wrap failed: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.AESGenerateAndWrapResponseData)
	if !ok {
		t.Fatalf("unexpected data type: %T", resp.Data)
	}
	if data.ItemDEKRawB64 == "" {
		t.Fatal("item_dek_raw_b64 should not be empty")
	}
	if data.WrappedItemDEK == "" {
		t.Fatal("wrapped_item_dek should not be empty")
	}

	rawItem, err := base64.StdEncoding.DecodeString(data.ItemDEKRawB64)
	if err != nil {
		t.Fatalf("decode item_dek: %v", err)
	}
	if len(rawItem) != 32 {
		t.Fatalf("item dek length = %d, want 32", len(rawItem))
	}

	// unwrap the wrapped Item DEK and check it matches the raw bytes
	unwrapped, err := UnwrapItemDEK(groupRaw, data.WrappedItemDEK)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	for i := range rawItem {
		if rawItem[i] != unwrapped[i] {
			t.Fatalf("item dek mismatch at byte %d", i)
		}
	}
}

// TestAESGenerateAndWrap_RejectsInvalidHandle: ensures an invalid handle is rejected.
func TestAESGenerateAndWrap_RejectsInvalidHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	cases := []struct {
		name   string
		handle string
	}{
		{"empty", ""},
		{"bogus", "this-handle-does-not-exist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: tc.handle})
			if resp.Success {
				t.Errorf("expected failure for %s", tc.name)
			}
		})
	}
}

// TestAESUnwrapAndEncrypt_Decrypt_Roundtrip: ensures encrypt → decrypt round
// trip recovers plaintext (Item DEK is re-unwrapped per call but produces the
// same result).
// The TestAESUnwrapAndDecrypt_* series was removed along with
// HandleAESUnwrapAndDecrypt. roundtrip / tampered / wrong-handle regression
// guards are covered by the unit tests of the clipboard sink action
// (HandleAESUnwrapAndDecryptToClipboard / TestHandle*Clipboard*).

// TestAESRewrap_* (cross-group Item DEK rewrap) regression guards were
// removed alongside HandleAESRewrap when the item_dek_grants schema was
// dropped.

// TestAES_Validation: covers the Validate() branch of all Item DEK actions at once.
func TestAES_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	t.Run("generate_and_wrap_empty", func(t *testing.T) {
		resp := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{})
		if resp.Success {
			t.Error("expected validation failure")
		}
	})
	t.Run("unwrap_and_encrypt_missing_fields", func(t *testing.T) {
		cases := []proto.AESUnwrapAndEncryptRequest{
			{GroupHandle: "h", PlaintextB64: "AA=="},       // wrapped_item_dek missing
			{WrappedItemDEK: "AA==", PlaintextB64: "AA=="}, // group_handle missing
			{WrappedItemDEK: "AA==", GroupHandle: "h"},     // plaintext missing
		}
		for i, c := range cases {
			if resp := HandleAESUnwrapAndEncrypt(deps, c); resp.Success {
				t.Errorf("case %d: expected failure", i)
			}
		}
	})
}

// The non-12B-IV guard is covered by AESUnwrapAndEncrypt + clipboard sink action unit tests.

// --- AESUnshareRewrapMeta regression guard ---

// TestAESUnshareRewrapMeta_Roundtrip: takes OLD wrap + value/meta ciphertext +
// extra dst group, re-encrypts everything with a new Item DEK, and issues
// grants for src + extras.
// raw plaintext appears 0 times in the response envelope (the response type
// itself has no plaintext_b64).
func TestAESUnshareRewrapMeta_Roundtrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	srcHandle, srcRaw := openSessionForFreshKey(t, deps)
	extraHandle, extraRaw := openSessionForFreshKey(t, deps)

	// (1) generate OLD Item DEK + encrypt value + meta with the same Item DEK
	gen := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: srcHandle})
	if !gen.Success {
		t.Fatalf("generate: %s", gen.Error)
	}
	oldWrapped := gen.Data.(proto.AESGenerateAndWrapResponseData).WrappedItemDEK
	oldItemDEKRaw, _ := base64.StdEncoding.DecodeString(
		gen.Data.(proto.AESGenerateAndWrapResponseData).ItemDEKRawB64,
	)

	const VALUE_PT = "secret-payload"
	const LABEL_PT = "label-text"
	const URL_PT = "https://example.com"
	const HOSTNAME_PT = "example.com"

	encValue, _ := AESGCMSeal(oldItemDEKRaw, []byte(VALUE_PT))
	encLabel, _ := AESGCMSeal(oldItemDEKRaw, []byte(LABEL_PT))
	encURL, _ := AESGCMSeal(oldItemDEKRaw, []byte(URL_PT))
	encHostname, _ := AESGCMSeal(oldItemDEKRaw, []byte(HOSTNAME_PT))

	// Split encValue into IV+ct to build ivB64/ctB64 (Base64 → IV(12)||ct → split)
	encValueRaw, _ := base64.StdEncoding.DecodeString(encValue)
	ivB64 := base64.StdEncoding.EncodeToString(encValueRaw[:12])
	ctB64 := base64.StdEncoding.EncodeToString(encValueRaw[12:])

	// (2) call UNSHARE_REENCRYPT — one extra dst
	resp := HandleAESUnshareRewrapMeta(deps, proto.AESUnshareRewrapMetaRequest{
		WrappedItemDEK: oldWrapped,
		SrcGroupHandle: srcHandle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		MetaFields: map[string]string{
			"label":           encLabel,
			"target_url":      encURL,
			"target_hostname": encHostname,
		},
		ExtraDstGroupHandles: []string{extraHandle},
	})
	if !resp.Success {
		t.Fatalf("unshare rewrap: %s", resp.Error)
	}
	data := resp.Data.(proto.AESUnshareRewrapMetaResponseData)

	// (3) response check: 2 grants (src + extra)
	if len(data.NewGrants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(data.NewGrants))
	}
	if data.NewGrants[0].GroupHandle != srcHandle {
		t.Errorf("first grant must be src handle")
	}
	if data.NewGrants[1].GroupHandle != extraHandle {
		t.Errorf("second grant must be extra handle")
	}

	// (4) regression guard: plaintext fields appear 0 times in the response envelope
	rawJSON, _ := json.Marshal(resp.Data)
	jsonStr := string(rawJSON)
	for _, plain := range []string{VALUE_PT, LABEL_PT, URL_PT, HOSTNAME_PT} {
		if strings.Contains(jsonStr, plain) {
			t.Errorf("response leaked plaintext %q (envelope: %s)", plain, jsonStr)
		}
	}
	// "value" is a legitimate field name (new_encrypted_value), so it's excluded — guard plaintext / secret only.
	for _, key := range []string{"plaintext_b64", "\"plaintext\"", "\"secret\""} {
		if strings.Contains(jsonStr, key) {
			t.Errorf("response contains forbidden field %q", key)
		}
	}

	// (5) round-trip via src grant + new encryptedValue — unwrap with extras → decrypt
	for _, grant := range data.NewGrants {
		var rawForGroup []byte
		switch grant.GroupHandle {
		case srcHandle:
			rawForGroup = srcRaw
		case extraHandle:
			rawForGroup = extraRaw
		default:
			t.Fatalf("unknown grant handle %s", grant.GroupHandle)
		}
		newItemDEK, err := UnwrapItemDEK(rawForGroup, grant.WrappedItemDEK)
		if err != nil {
			t.Fatalf("unwrap grant %s: %v", grant.GroupHandle, err)
		}
		// new value decrypt
		newValueRaw, _ := base64.StdEncoding.DecodeString(data.NewEncryptedValue)
		pt, err := AESGCMOpen(newItemDEK, newValueRaw[:12], newValueRaw[12:])
		if err != nil {
			t.Fatalf("open value via grant %s: %v", grant.GroupHandle, err)
		}
		if string(pt) != VALUE_PT {
			t.Errorf("value mismatch via grant %s: got %q", grant.GroupHandle, pt)
		}
		// meta decrypt
		for fkey, expected := range map[string]string{
			"label":           LABEL_PT,
			"target_url":      URL_PT,
			"target_hostname": HOSTNAME_PT,
		} {
			fieldRaw, _ := base64.StdEncoding.DecodeString(data.NewEncryptedFields[fkey])
			fpt, err := AESGCMOpen(newItemDEK, fieldRaw[:12], fieldRaw[12:])
			if err != nil {
				t.Fatalf("open meta %s via grant %s: %v", fkey, grant.GroupHandle, err)
			}
			if string(fpt) != expected {
				t.Errorf("meta %s mismatch via grant %s: got %q", fkey, grant.GroupHandle, fpt)
			}
		}
	}
}

func TestAESUnshareRewrapMeta_RejectsInvalidInput(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)
	gen := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{GroupHandle: handle})
	wrapped := gen.Data.(proto.AESGenerateAndWrapResponseData).WrappedItemDEK

	cases := []struct {
		name string
		req  proto.AESUnshareRewrapMetaRequest
	}{
		{
			name: "missing wrapped_item_dek",
			req: proto.AESUnshareRewrapMetaRequest{
				SrcGroupHandle: handle,
				IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 12)),
				CiphertextB64:  "AA==",
			},
		},
		{
			name: "bad iv length (8B)",
			req: proto.AESUnshareRewrapMetaRequest{
				WrappedItemDEK: wrapped,
				SrcGroupHandle: handle,
				IVB64:          base64.StdEncoding.EncodeToString(make([]byte, 8)),
				CiphertextB64:  "AA==",
			},
		},
		{
			name: "extra dst handle invalid",
			req: proto.AESUnshareRewrapMetaRequest{
				WrappedItemDEK:       wrapped,
				SrcGroupHandle:       handle,
				IVB64:                base64.StdEncoding.EncodeToString(make([]byte, 12)),
				CiphertextB64:        "AA==",
				ExtraDstGroupHandles: []string{""},
			},
		},
	}
	for _, tc := range cases {
		resp := HandleAESUnshareRewrapMeta(deps, tc.req)
		if resp.Success {
			t.Errorf("%s: expected failure", tc.name)
		}
	}
}

// --- App receiver method DI guard --------

func TestApp_HandleAESGenerateAndWrap_NoStoreHandle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// 32B Base64 — passes requireHandle (missing handle → rejected at store.Use step).
	resp := HandleAESGenerateAndWrap(deps, proto.AESGenerateAndWrapRequest{
		GroupHandle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if resp.Success {
		t.Fatalf("expected failure for unknown handle")
	}
	if !log.Contains("aes generate and wrap request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("aes generate and wrap successful") {
		t.Fatalf("must not log success on store miss")
	}
}
