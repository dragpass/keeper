// facade_aes_test.go: dispatcher-layer checks for Item DEK (aes_*) +
// Group session actions.
// (Handler-unit coverage lives in item_dek_actions_test.go; here we
//
//	look at the JSON envelope + dispatch coupling.) Same path works
//	after the group_handle migration.
//
// The `openTestGroupSession` helper is local to facade_aes_test.go.
// Composite facade tests seed their own keypair / device key on the
// NewApp + MemorySecretStore path.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// openTestGroupSession registers a raw 32B Group DEK directly into the
// store for dispatcher tests and returns the handle. Going via
// group_session_open through the dispatcher would require a user
// private key in the Keychain (extra fixture), so we use the store API
// directly. Auto-closes on test end.
func openTestGroupSession(t *testing.T, app *App, raw []byte) string {
	t.Helper()
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)
	store := app.GroupSessions
	handle, _, err := store.Open(rawCopy)
	if err != nil {
		t.Fatalf("openTestGroupSession: %v", err)
	}
	t.Cleanup(func() {
		store.Close(handle)
	})
	return handle
}

// TestHandleRequest_AESGenerateAndWrap_JSONRoundtrip verifies the
// action dispatches correctly and response fields are populated via the
// JSON-message envelope.
//
// Same dispatch path works after the group_dek_b64 → group_handle
// migration.
func TestHandleRequest_AESGenerateAndWrap_JSONRoundtrip(t *testing.T) {
	app := newFacadeTestApp()
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(i)
	}
	handle := openTestGroupSession(t, app, groupDEK)

	msg := fmt.Sprintf(
		`{"action":"aes_generate_and_wrap","request_id":"r-1","payload":{"group_handle":%q}}`,
		handle,
	)
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("aes_generate_and_wrap dispatch failed: %s", resp.Error)
	}
	if resp.RequestID != "r-1" {
		t.Errorf("request_id echo mismatch: got %q", resp.RequestID)
	}

	raw, _ := json.Marshal(resp.Data)
	var data AESGenerateAndWrapResponseData
	json.Unmarshal(raw, &data)
	if data.WrappedItemDEK == "" || data.ItemDEKRawB64 == "" {
		t.Error("response should populate wrapped_item_dek and item_dek_raw_b64")
	}
}

// TestHandleRequest_AES_FullRoundtrip verifies the full
// generate→encrypt→decrypt flow works through the dispatch layer.
//
// group_handle-based.
func TestHandleRequest_AES_FullRoundtrip(t *testing.T) {
	app := newFacadeTestApp()
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0x10 + i)
	}
	handle := openTestGroupSession(t, app, groupDEK)

	// 1) generate
	genMsg := fmt.Sprintf(`{"action":"aes_generate_and_wrap","payload":{"group_handle":%q}}`, handle)
	genResp := app.HandleRequest([]byte(genMsg))
	if !genResp.Success {
		t.Fatalf("generate: %s", genResp.Error)
	}
	rawGen, _ := json.Marshal(genResp.Data)
	var genData AESGenerateAndWrapResponseData
	json.Unmarshal(rawGen, &genData)

	// 2) encrypt
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("hello world"))
	encMsg := fmt.Sprintf(
		`{"action":"aes_unwrap_and_encrypt","payload":{"wrapped_item_dek":%q,"group_handle":%q,"plaintext_b64":%q}}`,
		genData.WrappedItemDEK, handle, plaintextB64,
	)
	encResp := app.HandleRequest([]byte(encMsg))
	if !encResp.Success {
		t.Fatalf("encrypt: %s", encResp.Error)
	}
	rawEnc, _ := json.Marshal(encResp.Data)
	var encData AESUnwrapAndEncryptResponseData
	json.Unmarshal(rawEnc, &encData)

	// 3) decrypt-to-clipboard (after legacy aes_unwrap_and_decrypt removal, verify via the sink path).
	//    Since the response has no plaintext, the regression guard is the success-response envelope + copied flag instead.
	decMsg := fmt.Sprintf(
		`{"action":"aes_unwrap_and_decrypt_to_clipboard","payload":{"wrapped_item_dek":%q,"group_handle":%q,"iv_b64":%q,"ciphertext_b64":%q,"clipboard_ttl_ms":30000}}`,
		genData.WrappedItemDEK, handle, encData.IVB64, encData.CiphertextB64,
	)
	decResp := app.HandleRequest([]byte(decMsg))
	if !decResp.Success {
		t.Fatalf("decrypt-to-clipboard: %s", decResp.Error)
	}
	rawDec, _ := json.Marshal(decResp.Data)
	var decData ClipboardCopyResponseData
	json.Unmarshal(rawDec, &decData)
	if !decData.Copied || decData.ClipboardTTLMs != 30000 {
		t.Errorf("expected {copied:true, ttl:30000}, got %+v", decData)
	}
}

// TestHandleRequest_GroupSession_FullLifecycle verifies the close /
// status actions work via the dispatcher. open is called directly
// since it needs the user RSA private key.
func TestHandleRequest_GroupSession_FullLifecycle(t *testing.T) {
	app := newFacadeTestApp()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	handle := openTestGroupSession(t, app, raw)

	// 1) status — handle exists + remaining > 0
	statusMsg := fmt.Sprintf(`{"action":"group_session_status","payload":{"group_handle":%q}}`, handle)
	statusResp := app.HandleRequest([]byte(statusMsg))
	if !statusResp.Success {
		t.Fatalf("status: %s", statusResp.Error)
	}
	rawStatus, _ := json.Marshal(statusResp.Data)
	var statusData GroupSessionStatusResponseData
	json.Unmarshal(rawStatus, &statusData)
	if !statusData.Exists {
		t.Error("status should report exists=true")
	}
	if statusData.RemainingMs <= 0 {
		t.Errorf("remaining_ms should be > 0, got %d", statusData.RemainingMs)
	}

	// 2) close
	closeMsg := fmt.Sprintf(`{"action":"group_session_close","payload":{"group_handle":%q}}`, handle)
	closeResp := app.HandleRequest([]byte(closeMsg))
	if !closeResp.Success {
		t.Fatalf("close: %s", closeResp.Error)
	}

	// 3) status after close — exists=false
	statusResp2 := app.HandleRequest([]byte(statusMsg))
	if !statusResp2.Success {
		t.Fatalf("status after close: %s", statusResp2.Error)
	}
	rawStatus2, _ := json.Marshal(statusResp2.Data)
	var statusData2 GroupSessionStatusResponseData
	json.Unmarshal(rawStatus2, &statusData2)
	if statusData2.Exists {
		t.Error("status after close should report exists=false")
	}

	// 4) close is idempotent — a second close also succeeds
	closeResp2 := app.HandleRequest([]byte(closeMsg))
	if !closeResp2.Success {
		t.Errorf("idempotent close: %s", closeResp2.Error)
	}
}
