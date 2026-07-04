// group_dek_composite_test.go — regression guard for the two raw-free
// composite actions in group_dek_composite.go (GroupDEKGenerateAndOpen /
// DEKRewrapForMember).
//
// Two core guarantees:
//
//  1. **crypto round-trip** — the composite action performs unwrap+wrap
//     correctly so that decrypting the wrap result with the corresponding
//     private key yields the original.
//  2. **raw bytes leak 0** — no raw Group DEK Base64 pattern appears in the
//     response serialization.
//
// **Additional defects caught:**
//   - regression where HandleGroupDEKGenerateAndOpen emits a success log on
//     an unparseable PEM (a.Logger DI guard)

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// setupHandlerKeyPair creates a temporary RSA keypair and stores it in deps's
// SecretStore. Needed because HandleDEKRewrapForMember reads the private key
// via keychain.GetPrivateKey(deps.Store). The earlier root location used
// keyring.MockInit + DefaultApp.Store; this package writes directly to
// deps.Store (= MemorySecretStore).
func setupHandlerKeyPair(t *testing.T, store keychain.SecretStore) (publicKeyPEM, privateKeyPEM string) {
	t.Helper()
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := keychain.SavePublicKey(store, kp.PublicKey); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}
	if err := keychain.SavePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	return kp.PublicKey, kp.PrivateKey
}

// ─── HandleGroupDEKGenerateAndOpen ──────────────────────────────────────

func TestHandleGroupDEKGenerateAndOpen_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{})
	if resp.Success {
		t.Fatal("expected validation failure when my_public_key is missing")
	}
}

func TestHandleGroupDEKGenerateAndOpen_BadPublicKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{
		MyPublicKey: "-----BEGIN PUBLIC KEY-----\nNOT-A-KEY\n-----END PUBLIC KEY-----",
	})
	if resp.Success {
		t.Fatal("expected failure for malformed public key")
	}
	if !strings.Contains(resp.Error, "parse my public key") {
		t.Errorf("error should mention parse failure, got: %q", resp.Error)
	}
}

// TestHandleGroupDEKGenerateAndOpen_RoundTrip: decrypt the response's
// encrypted_for_me_b64 with the corresponding private key and compare the
// resulting raw 32B with the raw 32B in the store pointed to by the handle —
// verifies the composite action used the same raw for both (a) the wrap in
// the response and (b) the store registration.
func TestHandleGroupDEKGenerateAndOpen_RoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, privPEM := setupHandlerKeyPair(t, store)

	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{
		MyPublicKey: pubPEM,
	})
	if !resp.Success {
		t.Fatalf("HandleGroupDEKGenerateAndOpen failed: %s", resp.Error)
	}

	var data proto.GroupDEKGenerateAndOpenResponseData
	rawJSON, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(rawJSON, &data)

	if data.GroupHandle == "" {
		t.Fatal("group_handle should not be empty")
	}
	if data.EncryptedForMeB64 == "" {
		t.Fatal("encrypted_for_me_b64 should not be empty")
	}
	if data.ExpiresAtMs == 0 {
		t.Fatal("expires_at_ms should not be zero")
	}
	t.Cleanup(func() {
		deps.GroupSessions.Close(data.GroupHandle)
	})

	// (a) decrypt response wrapped with private key → raw 32B
	encryptedRaw, err := base64.StdEncoding.DecodeString(data.EncryptedForMeB64)
	if err != nil {
		t.Fatalf("decode encrypted_for_me_b64: %v", err)
	}
	priv, err := crypto.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rawFromResp, err := crypto.DecryptData(priv, encryptedRaw)
	if err != nil {
		t.Fatalf("DecryptData (response): %v", err)
	}
	if len(rawFromResp) != 32 {
		t.Fatalf("rawFromResp length = %d, want 32", len(rawFromResp))
	}

	// (b) compare directly to store's raw 32B via Use on the handle
	useErr := deps.GroupSessions.Use(data.GroupHandle, func(rawDEK []byte) error {
		if len(rawDEK) != 32 {
			t.Fatalf("rawDEK in store length = %d, want 32", len(rawDEK))
		}
		for i := range rawFromResp {
			if rawFromResp[i] != rawDEK[i] {
				t.Fatalf("byte %d mismatch: response=%#x store=%#x", i, rawFromResp[i], rawDEK[i])
			}
		}
		return nil
	})
	if useErr != nil {
		t.Fatalf("store.Use: %v", useErr)
	}
}

// TestHandleGroupDEKGenerateAndOpen_NoRawInResponse: the raw Group DEK Base64
// pattern must not leak anywhere in the response serialization. The response
// guarantees wrapped + handle only; raw itself must never enter the response.
func TestHandleGroupDEKGenerateAndOpen_NoRawInResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)
	pubPEM, _ := setupHandlerKeyPair(t, store)

	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{
		MyPublicKey: pubPEM,
	})
	if !resp.Success {
		t.Fatalf("HandleGroupDEKGenerateAndOpen failed: %s", resp.Error)
	}

	var data proto.GroupDEKGenerateAndOpenResponseData
	rawJSON, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(rawJSON, &data)
	t.Cleanup(func() {
		deps.GroupSessions.Close(data.GroupHandle)
	})

	// Read raw 32B from the store and verify its Base64 does not appear anywhere in the response JSON.
	var rawB64 string
	useErr := deps.GroupSessions.Use(data.GroupHandle, func(rawDEK []byte) error {
		rawB64 = base64.StdEncoding.EncodeToString(rawDEK)
		return nil
	})
	if useErr != nil {
		t.Fatalf("store.Use: %v", useErr)
	}

	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), rawB64) {
		t.Fatalf("response JSON contains raw Group DEK Base64 — leak!\nraw: %s\nresp: %s", rawB64, respJSON)
	}
}

// ─── HandleDEKRewrapForMember ───────────────────────────────────────────

func TestHandleDEKRewrapForMember_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	cases := []struct {
		name string
		req  proto.DEKRewrapForMemberRequest
	}{
		{"missing wrapped", proto.DEKRewrapForMemberRequest{OtherPublicKey: "pk"}},
		{"missing other pub", proto.DEKRewrapForMemberRequest{WrappedForMeB64: "wmb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleDEKRewrapForMember(deps, tc.req)
			if resp.Success {
				t.Errorf("expected validation failure for %q", tc.name)
			}
		})
	}
}

func TestHandleDEKRewrapForMember_BadPublicKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	resp := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: base64.StdEncoding.EncodeToString([]byte("doesnt-matter")),
		OtherPublicKey:  "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----",
	})
	if resp.Success {
		t.Fatal("expected failure for malformed other public key")
	}
}

func TestHandleDEKRewrapForMember_RoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)

	// other member's keypair
	otherKP, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair (other): %v", err)
	}

	// seed: deterministic 32B Group DEK + wrap with my public key
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xA0 + i)
	}
	myPub, err := crypto.ParsePublicKey(myPubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey (my): %v", err)
	}
	wrappedForMe, err := crypto.EncryptData(myPub, groupDEK)
	if err != nil {
		t.Fatalf("EncryptData (my): %v", err)
	}

	// invoke composite action
	resp := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: base64.StdEncoding.EncodeToString(wrappedForMe),
		OtherPublicKey:  otherKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("HandleDEKRewrapForMember failed: %s", resp.Error)
	}

	var data proto.DEKRewrapForMemberResponseData
	rawJSON, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(rawJSON, &data)
	if data.EncryptedForOtherB64 == "" {
		t.Fatal("encrypted_for_other_b64 should not be empty")
	}

	// decrypt with the other party's private key → must equal the original Group DEK
	otherPriv, err := crypto.ParsePrivateKey(otherKP.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey (other): %v", err)
	}
	wrappedForOther, err := base64.StdEncoding.DecodeString(data.EncryptedForOtherB64)
	if err != nil {
		t.Fatalf("decode encrypted_for_other: %v", err)
	}
	decrypted, err := crypto.DecryptData(otherPriv, wrappedForOther)
	if err != nil {
		t.Fatalf("DecryptData (other): %v", err)
	}
	if len(decrypted) != 32 {
		t.Fatalf("decrypted length = %d, want 32", len(decrypted))
	}
	for i := range groupDEK {
		if decrypted[i] != groupDEK[i] {
			t.Fatalf("byte %d mismatch: orig=%#x decrypted=%#x", i, groupDEK[i], decrypted[i])
		}
	}
}

// TestHandleDEKRewrapForMember_NoRawInResponse: the raw Group DEK Base64
// pattern must not leak into the response. Unwrap happens only inside the
// Keeper; the response contains only the new wrapped value.
func TestHandleDEKRewrapForMember_NoRawInResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)

	otherKP, _ := crypto.GenerateRSAKeyPair()
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xB0 + i)
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)

	myPub, _ := crypto.ParsePublicKey(myPubPEM)
	wrappedForMe, _ := crypto.EncryptData(myPub, groupDEK)

	resp := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: base64.StdEncoding.EncodeToString(wrappedForMe),
		OtherPublicKey:  otherKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("HandleDEKRewrapForMember failed: %s", resp.Error)
	}

	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), rawB64) {
		t.Fatalf("response JSON contains raw Group DEK Base64 — leak!\nraw: %s\nresp: %s", rawB64, respJSON)
	}
}

// --- App receiver method DI guard --------

func TestApp_HandleGroupDEKGenerateAndOpen_RejectsBadPEM(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// Fake PEM that passes validate (has PEM prefix) but fails ParsePublicKey.
	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{
		MyPublicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
	})
	if resp.Success {
		t.Fatalf("expected failure for unparseable public key")
	}
	if !log.Contains("failed to parse my public key") {
		t.Fatalf("expected parse-error log, got: %v", log.Messages())
	}
	if log.Contains("group dek generate and open successful") {
		t.Fatalf("must not log success on parse failure")
	}
}
