// facade_composite_dek_test.go: dispatch coupling tests for composite DEK
// actions + personal DEK suite. Handler-unit coverage lives in
// dek_actions_test.go / group_dek_composite_actions_test.go — here we
// look at the JSON envelope + dispatch coupling.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// TestHandleRequest_GroupDEKGenerateAndOpen_JSONDispatch verifies that
// the composite action is invoked via the dispatcher and the response
// includes group_handle + encrypted_for_me_b64.
func TestHandleRequest_GroupDEKGenerateAndOpen_JSONDispatch(t *testing.T) {
	app := newFacadeTestApp()
	pubPEM, _ := setupAppKeyPair(t, app)
	pubJSON, _ := json.Marshal(pubPEM)
	msg := fmt.Sprintf(`{"action":"group_dek_generate_and_open","request_id":"r-gen","payload":{"my_public_key":%s}}`, pubJSON)
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("dispatch failed: %s", resp.Error)
	}
	if resp.RequestID != "r-gen" {
		t.Errorf("request_id echo: got %q", resp.RequestID)
	}
	rawJSON, _ := json.Marshal(resp.Data)
	var data GroupDEKGenerateAndOpenResponseData
	json.Unmarshal(rawJSON, &data)
	if data.GroupHandle == "" {
		t.Error("group_handle should not be empty")
	}
	if data.EncryptedForMeB64 == "" {
		t.Error("encrypted_for_me_b64 should not be empty")
	}
	t.Cleanup(func() {
		app.GroupSessions.Close(data.GroupHandle)
	})
}

// TestHandleRequest_DEKRewrapForMember_JSONDispatch verifies that the
// composite action is invoked via the dispatcher and the response
// includes encrypted_for_other_b64.
func TestHandleRequest_DEKRewrapForMember_JSONDispatch(t *testing.T) {
	app := newFacadeTestApp()
	myPubPEM, _ := setupAppKeyPair(t, app)
	otherKP, _ := GenerateRSAKeyPair()

	// Seed raw + wrap with my public key
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(0x10 + i)
	}
	myPub, _ := ParsePublicKey(myPubPEM)
	wrappedForMe, _ := EncryptData(myPub, dek)
	wrappedB64 := base64.StdEncoding.EncodeToString(wrappedForMe)

	wrappedJSON, _ := json.Marshal(wrappedB64)
	pubJSON, _ := json.Marshal(otherKP.PublicKey)
	msg := fmt.Sprintf(
		`{"action":"dek_rewrap_for_member","request_id":"r-rewrap","payload":{"wrapped_for_me_b64":%s,"other_public_key":%s}}`,
		wrappedJSON, pubJSON,
	)
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("dispatch failed: %s", resp.Error)
	}
	if resp.RequestID != "r-rewrap" {
		t.Errorf("request_id echo: got %q", resp.RequestID)
	}
	rawResp, _ := json.Marshal(resp.Data)
	var data DEKRewrapForMemberResponseData
	json.Unmarshal(rawResp, &data)
	if data.EncryptedForOtherB64 == "" {
		t.Error("encrypted_for_other_b64 should not be empty")
	}
}

// TestHandleRequest_DEKGenerateAndWrapPassword_JSONDispatch verifies
// dispatch works and the response includes encrypted_dek_b64.
func TestHandleRequest_DEKGenerateAndWrapPassword_JSONDispatch(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"dek_generate_and_wrap_password","request_id":"r-dek","payload":{"password":"secret"}}`
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("dispatch failed: %s", resp.Error)
	}
	if resp.RequestID != "r-dek" {
		t.Errorf("request_id echo: got %q", resp.RequestID)
	}
	raw, _ := json.Marshal(resp.Data)
	var data DEKGenerateAndWrapPasswordResponseData
	json.Unmarshal(raw, &data)
	if data.EncryptedDEKB64 == "" {
		t.Error("encrypted_dek_b64 should not be empty")
	}
}

// TestHandleRequest_DEKGenerateAndWrapDual_JSONDispatch verifies dual
// wrap JSON envelope dispatch and the two response fields
// (password_wrapped_dek_b64, device_wrapped_dek_b64).
//
// No device_key_b64 in the payload — the handler fetches from the Keychain,
// so seed it ahead of time via saveDeviceKey.
func TestHandleRequest_DEKGenerateAndWrapDual_JSONDispatch(t *testing.T) {
	app := newFacadeTestApp()
	if err := app.saveDeviceKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("saveDeviceKey: %v", err)
	}
	msg := `{"action":"dek_generate_and_wrap_dual","request_id":"r-dual","payload":{"password":"secret"}}`
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("dispatch failed: %s", resp.Error)
	}
	if resp.RequestID != "r-dual" {
		t.Errorf("request_id echo: got %q", resp.RequestID)
	}
	raw, _ := json.Marshal(resp.Data)
	var data DEKGenerateAndWrapDualResponseData
	json.Unmarshal(raw, &data)
	if data.PasswordWrappedDEKB64 == "" || data.DeviceWrappedDEKB64 == "" {
		t.Error("both wrap outputs should be populated")
	}
}

// TestHandleRequest_DEKUnwrapEncrypt_FullFlow verifies the full flow
// signup → unwrap_and_encrypt → unwrap_and_decrypt through the dispatch
// layer.
func TestHandleRequest_DEKUnwrapEncrypt_FullFlow(t *testing.T) {
	app := newFacadeTestApp()
	if err := app.saveDeviceKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("saveDeviceKey: %v", err)
	}

	signupMsg := `{"action":"dek_generate_and_wrap_dual","payload":{"password":"p"}}`
	signupResp := app.HandleRequest([]byte(signupMsg))
	if !signupResp.Success {
		t.Fatalf("signup: %s", signupResp.Error)
	}
	signupRaw, _ := json.Marshal(signupResp.Data)
	var signupData DEKGenerateAndWrapDualResponseData
	json.Unmarshal(signupRaw, &signupData)

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	encMsg := fmt.Sprintf(
		`{"action":"dek_unwrap_and_encrypt","request_id":"r-enc","payload":{"encrypted_dek_b64":%q,"plaintext_b64":%q}}`,
		signupData.DeviceWrappedDEKB64, plaintextB64,
	)
	encResp := app.HandleRequest([]byte(encMsg))
	if !encResp.Success {
		t.Fatalf("encrypt: %s", encResp.Error)
	}
	if encResp.RequestID != "r-enc" {
		t.Errorf("request_id echo: got %q", encResp.RequestID)
	}
	encRaw, _ := json.Marshal(encResp.Data)
	var encData DEKUnwrapAndEncryptResponseData
	json.Unmarshal(encRaw, &encData)

	decMsg := fmt.Sprintf(
		`{"action":"dek_unwrap_and_decrypt_to_clipboard","payload":{"encrypted_dek_b64":%q,"iv_b64":%q,"ciphertext_b64":%q,"clipboard_ttl_ms":30000}}`,
		signupData.DeviceWrappedDEKB64, encData.IVB64, encData.CiphertextB64,
	)
	decResp := app.HandleRequest([]byte(decMsg))
	if !decResp.Success {
		t.Fatalf("decrypt-to-clipboard: %s", decResp.Error)
	}
	decRaw, _ := json.Marshal(decResp.Data)
	var decData ClipboardCopyResponseData
	json.Unmarshal(decRaw, &decData)
	if !decData.Copied || decData.ClipboardTTLMs != 30000 {
		t.Errorf("expected {copied:true, ttl:30000}, got %+v", decData)
	}
}

// TestHandleRequest_DEKRotateToDeviceKey_FullFlow verifies the
// signup → rotate full flow through the dispatch layer.
//
// Replace the keychain deviceKey with a new value right before rotate.
func TestHandleRequest_DEKRotateToDeviceKey_FullFlow(t *testing.T) {
	app := newFacadeTestApp()
	if err := app.saveDeviceKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("saveDeviceKey (1): %v", err)
	}

	signupMsg := `{"action":"dek_generate_and_wrap_dual","payload":{"password":"login-pw"}}`
	signupResp := app.HandleRequest([]byte(signupMsg))
	if !signupResp.Success {
		t.Fatalf("signup: %s", signupResp.Error)
	}
	signupRaw, _ := json.Marshal(signupResp.Data)
	var signupData DEKGenerateAndWrapDualResponseData
	json.Unmarshal(signupRaw, &signupData)

	// Replace the keychain deviceKey with a new value (simulates a different device).
	deviceKey2 := make([]byte, 32)
	for i := range deviceKey2 {
		deviceKey2[i] = byte(0xAA)
	}
	if err := app.saveDeviceKey(base64.StdEncoding.EncodeToString(deviceKey2)); err != nil {
		t.Fatalf("saveDeviceKey (2): %v", err)
	}

	rotateMsg := fmt.Sprintf(
		`{"action":"dek_rotate_to_device_key","request_id":"r-rotate","payload":{"password":"login-pw","encrypted_dek_b64":%q}}`,
		signupData.PasswordWrappedDEKB64,
	)
	rotateResp := app.HandleRequest([]byte(rotateMsg))
	if !rotateResp.Success {
		t.Fatalf("rotate: %s", rotateResp.Error)
	}
	if rotateResp.RequestID != "r-rotate" {
		t.Errorf("request_id echo: got %q", rotateResp.RequestID)
	}
	rotateRaw, _ := json.Marshal(rotateResp.Data)
	var rotateData DEKRotateToDeviceKeyResponseData
	json.Unmarshal(rotateRaw, &rotateData)
	if rotateData.DeviceWrappedDEKB64 == "" {
		t.Error("device_wrapped_dek_b64 should be populated")
	}
}
