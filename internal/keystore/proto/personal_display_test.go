package proto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPersonalDisplayOperationBindsSelectedTokenAndFrame(t *testing.T) {
	op := PersonalDisplayOperation{
		Token:              []byte("selected personal ciphertext"),
		Ciphertext:         []byte("sealed bytes"),
		FramePublicKeySPKI: []byte("frame key"),
	}
	copy(op.Challenge[:], bytes.Repeat([]byte{3}, 32))
	copy(op.IV[:], bytes.Repeat([]byte{4}, 12))
	first := PersonalDisplayOperationDigest(op)
	if first == [32]byte{} {
		t.Fatal("empty personal display operation digest")
	}
	op.Token = []byte("another selected token")
	if PersonalDisplayOperationDigest(op) == first {
		t.Fatal("operation digest admitted another selected token")
	}
	op.Token = []byte("selected personal ciphertext")
	op.FramePublicKeySPKI = []byte("another frame key")
	if PersonalDisplayOperationDigest(op) == first {
		t.Fatal("operation digest admitted another frame")
	}
}

func TestPersonalDisplayPrepareRequiresOneFrameAndSession(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	req := PersonalDisplayPrepareRequest{
		Token:                 "selected token",
		TokenAADB64:           base64.StdEncoding.EncodeToString([]byte("dragpass.drag-display|1|personal|1|||0|")),
		IVB64:                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 12)),
		CiphertextB64:         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(spki),
		TokenID:               "33333333-3333-4333-8333-333333333333",
		SessionIssuedAtNanos:  "1000000001",
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid personal preparation refused: %v", err)
	}
	req.FramePublicKeySPKIB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 80))
	if req.Validate() == nil {
		t.Fatal("non-P-256 receiving frame admitted")
	}
}

func TestPersonalDisplayDecisionRejectsUnboundOrExpiredShape(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	d := PersonalDisplayDecision{
		Challenge:            challenge,
		AccountID:            "11111111-1111-4111-8111-111111111111",
		DeviceID:             "22222222-2222-4222-8222-222222222222",
		TokenID:              "33333333-3333-4333-8333-333333333333",
		SessionIssuedAtNanos: 1000000001,
		WrapDigest:           strings.Repeat("a", 64),
		OperationDigest:      strings.Repeat("b", 64),
		FrameKeyDigest:       strings.Repeat("c", 64),
		IssuedAt:             1000, ExpiresAt: 1010, ServerKeyVersion: 1,
		Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("valid personal decision shape refused: %v", err)
	}
	changed := d
	changed.ExpiresAt++
	if changed.Validate() == nil {
		t.Fatal("personal decision admitted an extended validity window")
	}
	changed = d
	changed.FrameKeyDigest = strings.Repeat("0", 64)
	if changed.Validate() == nil {
		t.Fatal("personal decision admitted an empty frame binding")
	}
	if got := PersonalDisplayDecisionCanonical(d); !strings.HasPrefix(got, "dragpass.personal.display|1|") {
		t.Fatal("personal decision uses the wrong signature domain")
	}
}
