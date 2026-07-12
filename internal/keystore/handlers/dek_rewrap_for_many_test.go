// dek_rewrap_for_many_test.go — multi-recipient rewrap composite tests
// (HandleDEKUnwrapAndRewrapForMany).
//
// Guarantees mirrored from the dek_rewrap_for_member family:
//
//  1. **validation** — rejects requests missing wrapped_for_me_b64, an empty
//     recipient list, or a non-PEM recipient key.
//  2. **not_found** — a missing identity private-key slot returns the
//     not_found error_code.
//  3. **crypto round-trip** — the OLD Group DEK wrapped to my public key and
//     re-wrapped by the composite action to N member keys must decrypt with
//     each member's private key to the same original value.
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
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleDEKUnwrapAndRewrapForMany_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	validPEM := "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
	validWrap := base64.StdEncoding.EncodeToString([]byte("x"))
	cases := []struct {
		name string
		req  proto.DEKUnwrapAndRewrapForManyRequest
	}{
		{"missing wrapped", proto.DEKUnwrapAndRewrapForManyRequest{RecipientPublicKeys: []string{validPEM}}},
		{"empty recipients", proto.DEKUnwrapAndRewrapForManyRequest{WrappedForMeB64: validWrap, RecipientPublicKeys: nil}},
		{"non-pem recipient", proto.DEKUnwrapAndRewrapForManyRequest{WrappedForMeB64: validWrap, RecipientPublicKeys: []string{validPEM, "not-a-pem"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleDEKUnwrapAndRewrapForMany(deps, tc.req)
			if resp.Success {
				t.Errorf("expected validation failure for %q, got success", tc.name)
			}
		})
	}
}

// A missing identity private-key slot must surface not_found.
func TestHandleDEKUnwrapAndRewrapForMany_MissingPrivateKey(t *testing.T) {
	deps, _, _ := newTestDeps(t) // no keypair set up

	recipientKP, _ := crypto.GenerateRSAKeyPair()
	resp := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64:     base64.StdEncoding.EncodeToString([]byte("doesnt-matter")),
		RecipientPublicKeys: []string{recipientKP.PublicKey},
	})
	if resp.Success {
		t.Fatal("expected failure when identity private key slot is absent")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Errorf("expected error_code=not_found, got %q", resp.ErrorCode)
	}
}

func TestHandleDEKUnwrapAndRewrapForMany_RoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)

	// deterministic 32B OLD Group DEK wrapped to my public key
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

	// three recipient keypairs — each must recover the OLD Group DEK
	recipients := make([]*crypto.KeyPair, 3)
	pems := make([]string, 3)
	for i := range recipients {
		kp, err := crypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair (recipient %d): %v", i, err)
		}
		recipients[i] = kp
		pems[i] = kp.PublicKey
	}

	resp := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64:     base64.StdEncoding.EncodeToString(wrappedForMe),
		RecipientPublicKeys: pems,
	})
	if !resp.Success {
		t.Fatalf("HandleDEKUnwrapAndRewrapForMany failed: %s", resp.Error)
	}

	var data proto.DEKUnwrapAndRewrapForManyResponseData
	rawJSON, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(rawJSON, &data)
	if len(data.EncryptedForRecipientsB64) != len(pems) {
		t.Fatalf("wraps count = %d, want %d", len(data.EncryptedForRecipientsB64), len(pems))
	}

	for i, wrapB64 := range data.EncryptedForRecipientsB64 {
		priv, err := crypto.ParsePrivateKey(recipients[i].PrivateKey)
		if err != nil {
			t.Fatalf("ParsePrivateKey (recipient %d): %v", i, err)
		}
		raw, err := base64.StdEncoding.DecodeString(wrapB64)
		if err != nil {
			t.Fatalf("decode wrap %d: %v", i, err)
		}
		decrypted, err := crypto.DecryptData(priv, raw)
		if err != nil {
			t.Fatalf("DecryptData (recipient %d): %v", i, err)
		}
		if len(decrypted) != 32 {
			t.Fatalf("recipient %d decrypted length = %d, want 32", i, len(decrypted))
		}
		for j := range groupDEK {
			if decrypted[j] != groupDEK[j] {
				t.Fatalf("recipient %d decrypted[%d] = %#x, want %#x — rewrap corrupted Group DEK",
					i, j, decrypted[j], groupDEK[j])
			}
		}
	}
}

func TestHandleDEKUnwrapAndRewrapForMany_NoRawInResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)

	groupDEK := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)
	myPub, _ := crypto.ParsePublicKey(myPubPEM)
	wrappedForMe, _ := crypto.EncryptData(myPub, groupDEK)

	recipientKP, _ := crypto.GenerateRSAKeyPair()
	resp := HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64:     base64.StdEncoding.EncodeToString(wrappedForMe),
		RecipientPublicKeys: []string{recipientKP.PublicKey},
	})
	if !resp.Success {
		t.Fatalf("HandleDEKUnwrapAndRewrapForMany failed: %s", resp.Error)
	}

	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), rawB64) {
		t.Errorf("raw group DEK Base64 leaked into response: %s", string(respJSON))
	}
	if strings.Contains(strings.ToUpper(string(respJSON)), "DEADBEEF") {
		t.Errorf("raw group DEK hex pattern leaked into response: %s", string(respJSON))
	}
}
