// archive_rewrap_test.go — break-glass re-grant composite tests
// (HandleArchiveUnwrapAndRewrap).
//
// Guarantees mirrored from the dek_rewrap_for_member family:
//
//  1. **validation** — rejects requests missing wrapped_for_archive_b64 /
//     recipient_public_key.
//  2. **not_found** — a missing archive private-key slot returns the
//     not_found error_code (re-bootstrap signal to the Extension).
//  3. **crypto round-trip** — a Group DEK wrapped to the archive public key
//     and re-wrapped by the composite action to a member key must decrypt
//     with the member's private key to the same original value.
//  4. **no raw leak** — the raw Group DEK must not appear in the response
//     serialization.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleArchiveUnwrapAndRewrap_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	cases := []struct {
		name string
		req  proto.ArchiveUnwrapAndRewrapRequest
	}{
		{"missing wrapped", proto.ArchiveUnwrapAndRewrapRequest{RecipientPublicKey: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"}},
		{"missing recipient", proto.ArchiveUnwrapAndRewrapRequest{WrappedForArchiveB64: base64.StdEncoding.EncodeToString([]byte("x"))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleArchiveUnwrapAndRewrap(deps, tc.req)
			if resp.Success {
				t.Errorf("expected validation failure for %q, got success", tc.name)
			}
		})
	}
}

// A missing archive slot must surface not_found so the Extension can prompt
// the owner to enable the archive key first.
func TestHandleArchiveUnwrapAndRewrap_MissingArchiveSlot(t *testing.T) {
	deps, _, _ := newTestDeps(t) // no archive private key stored

	recipientKP, _ := crypto.GenerateRSAKeyPair()
	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString([]byte("doesnt-matter")),
		RecipientPublicKey:   recipientKP.PublicKey,
	})
	if resp.Success {
		t.Fatal("expected failure when archive private key slot is absent")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Errorf("expected error_code=not_found, got %q", resp.ErrorCode)
	}
}

func TestHandleArchiveUnwrapAndRewrap_RoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t)

	// Archive keypair — private half stored in the archive slot, public half
	// used to wrap the OLD Group DEK (the org_owner_archive grant).
	archiveKP, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair (archive): %v", err)
	}
	if err := keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey); err != nil {
		t.Fatalf("SaveArchivePrivateKey: %v", err)
	}

	// Target member keypair — decrypts the re-wrap output.
	memberKP, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair (member): %v", err)
	}

	// Deterministic 32B Group DEK wrapped to the archive public key.
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xA0 + i)
	}
	archivePub, err := crypto.ParsePublicKey(archiveKP.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey (archive): %v", err)
	}
	wrappedForArchive, err := crypto.EncryptData(archivePub, groupDEK)
	if err != nil {
		t.Fatalf("EncryptData (archive): %v", err)
	}

	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrappedForArchive),
		RecipientPublicKey:   memberKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("HandleArchiveUnwrapAndRewrap failed: %s", resp.Error)
	}

	data, ok := resp.Data.(proto.ArchiveUnwrapAndRewrapResponseData)
	if !ok {
		t.Fatalf("unexpected response type: %T", resp.Data)
	}
	if data.EncryptedForOtherB64 == "" {
		t.Fatal("encrypted_for_other_b64 should not be empty")
	}

	// Decrypt with the member private key and compare to the original DEK.
	memberPriv, err := crypto.ParsePrivateKey(memberKP.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey (member): %v", err)
	}
	newEncryptedRaw, err := base64.StdEncoding.DecodeString(data.EncryptedForOtherB64)
	if err != nil {
		t.Fatalf("decode encrypted_for_other_b64: %v", err)
	}
	decrypted, err := crypto.DecryptData(memberPriv, newEncryptedRaw)
	if err != nil {
		t.Fatalf("DecryptData (member): %v", err)
	}
	if len(decrypted) != 32 {
		t.Fatalf("decrypted length = %d, want 32", len(decrypted))
	}
	for i := range groupDEK {
		if decrypted[i] != groupDEK[i] {
			t.Fatalf("decrypted[%d] = %#x, want %#x — rewrap corrupted Group DEK",
				i, decrypted[i], groupDEK[i])
		}
	}
}

func TestHandleArchiveUnwrapAndRewrap_NoRawInResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)

	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	memberKP, _ := crypto.GenerateRSAKeyPair()

	groupDEK := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)

	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrappedForArchive, _ := crypto.EncryptData(archivePub, groupDEK)

	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrappedForArchive),
		RecipientPublicKey:   memberKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("HandleArchiveUnwrapAndRewrap failed: %s", resp.Error)
	}

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal(resp): %v", err)
	}
	if strings.Contains(string(jsonBytes), rawB64) {
		t.Errorf("raw group DEK Base64 leaked into response: %s", string(jsonBytes))
	}
	if strings.Contains(strings.ToUpper(string(jsonBytes)), "DEADBEEF") {
		t.Errorf("raw group DEK hex pattern leaked into response: %s", string(jsonBytes))
	}
}
