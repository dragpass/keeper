// account_key_trust_fixture_test.go — the cross-repo account key trust vector.
//
// testdata/account-key-trust-v1.json is copied to dragpass-control-plane
// docs/testing/fixtures/ and read by the TypeScript side too. Its whole job is
// to pin bytes that three independent implementations have to agree on: the
// fingerprint of a PEM, the canonical string a statement signs, and the
// signatures over it. The formula only works if the bytes are identical, and a
// mismatch is silent — two repos simply stop recognising each other's
// fingerprints. This test is the Go half of that agreement.
//
// Field names here must stay exactly as the contract lists them
// (dragpass-control-plane docs/exec-plans/active/account-key-trust-implementation.md
// §9); the TS consumer reads the same keys.

package keystore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type accountKeyTrustFixture struct {
	FixtureVersion int    `json:"fixture_version"`
	TestOnly       bool   `json:"test_only"`
	AccountID      string `json:"account_id"`

	OldPublicKeyPEM string `json:"old_public_key_pem"`
	NewPublicKeyPEM string `json:"new_public_key_pem"`
	OldPublicKeyB64 string `json:"old_public_key_b64"`
	NewPublicKeyB64 string `json:"new_public_key_b64"`
	OldFingerprint  string `json:"old_fingerprint"`
	NewFingerprint  string `json:"new_fingerprint"`

	DeviceKeyStyleFingerprint string `json:"device_key_style_fingerprint"`

	RotatedAt       int64  `json:"rotated_at"`
	Reason          string `json:"reason"`
	CanonicalUTF8   string `json:"canonical_utf8"`
	CanonicalHex    string `json:"canonical_hex"`
	OldSignatureB64 string `json:"old_signature_b64"`
	NewSignatureB64 string `json:"new_signature_b64"`

	NegativeWrongSigner struct {
		NewSignatureB64         string `json:"new_signature_b64"`
		WrongSignerPublicKeyPEM string `json:"wrong_signer_public_key_pem"`
		WrongSignerPublicKeyB64 string `json:"wrong_signer_public_key_b64"`
	} `json:"negative_wrong_signer"`

	NegativeBrokenChain struct {
		CanonicalUTF8 string                     `json:"canonical_utf8"`
		Statement     proto.KeyRotationStatement `json:"statement"`
	} `json:"negative_broken_chain"`

	PinRecordJSON struct {
		JSON       string `json:"json"`
		ByteLength int    `json:"byte_length"`
	} `json:"pin_record_json"`
}

func loadAccountKeyTrustFixture(t *testing.T) accountKeyTrustFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/account-key-trust-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture accountKeyTrustFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.FixtureVersion != 1 || !fixture.TestOnly {
		t.Fatalf("fixture header = version %d test_only %t, want 1/true",
			fixture.FixtureVersion, fixture.TestOnly)
	}
	return fixture
}

// The Base64 and PEM forms of each key have to be the same bytes, since the
// server stores one and the Keeper holds the other.
func TestAccountKeyTrustFixture_KeyFormsAgree(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	for _, pair := range []struct {
		name string
		pem  string
		b64  string
	}{
		{"old", fixture.OldPublicKeyPEM, fixture.OldPublicKeyB64},
		{"new", fixture.NewPublicKeyPEM, fixture.NewPublicKeyB64},
	} {
		decoded, err := base64.StdEncoding.DecodeString(pair.b64)
		if err != nil {
			t.Fatalf("%s public key b64: %v", pair.name, err)
		}
		if string(decoded) != pair.pem {
			t.Fatalf("%s public key b64 does not decode to its PEM", pair.name)
		}
		if _, err := crypto.ParsePublicKey(pair.pem); err != nil {
			t.Fatalf("%s public key does not parse: %v", pair.name, err)
		}
	}
}

// The fingerprint formula: hex(sha256(pem bytes)), from either form.
func TestAccountKeyTrustFixture_Fingerprints(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	if got := crypto.AccountKeyFingerprint([]byte(fixture.OldPublicKeyPEM)); got != fixture.OldFingerprint {
		t.Fatalf("old fingerprint = %q, want %q", got, fixture.OldFingerprint)
	}
	if got := crypto.AccountKeyFingerprint([]byte(fixture.NewPublicKeyPEM)); got != fixture.NewFingerprint {
		t.Fatalf("new fingerprint = %q, want %q", got, fixture.NewFingerprint)
	}

	// Going through the Base64 column the way the server does must land on
	// the same value.
	decoded, err := base64.StdEncoding.DecodeString(fixture.NewPublicKeyB64)
	if err != nil {
		t.Fatalf("decode new_public_key_b64: %v", err)
	}
	if got := crypto.AccountKeyFingerprint(decoded); got != fixture.NewFingerprint {
		t.Fatalf("fingerprint via base64 decode = %q, want %q", got, fixture.NewFingerprint)
	}
}

// The negative vector: hashing the Base64 string instead of the PEM bytes is
// the device-key formula and gives a different value. An implementation that
// produces this where an account fingerprint belongs has used the wrong one.
func TestAccountKeyTrustFixture_DeviceKeyStyleIsNotAnAccountFingerprint(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	sum := sha256.Sum256([]byte(fixture.NewPublicKeyB64))
	if got := hex.EncodeToString(sum[:]); got != fixture.DeviceKeyStyleFingerprint {
		t.Fatalf("device-key-style fingerprint = %q, want %q", got, fixture.DeviceKeyStyleFingerprint)
	}
	if fixture.DeviceKeyStyleFingerprint == fixture.NewFingerprint ||
		fixture.DeviceKeyStyleFingerprint == fixture.OldFingerprint {
		t.Fatal("device-key-style fingerprint collides with an account fingerprint; " +
			"the vector cannot catch the mistake it exists for")
	}
}

// The canonical string and its bytes.
func TestAccountKeyTrustFixture_Canonical(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	built := proto.KeyRotationCanonical(
		fixture.AccountID, fixture.OldFingerprint, fixture.NewFingerprint,
		fixture.RotatedAt, fixture.Reason,
	)
	if built != fixture.CanonicalUTF8 {
		t.Fatalf("canonical = %q, want %q", built, fixture.CanonicalUTF8)
	}
	if got := hex.EncodeToString([]byte(built)); got != fixture.CanonicalHex {
		t.Fatalf("canonical hex = %q, want %q", got, fixture.CanonicalHex)
	}
}

// Both signatures verify under their own key, and the whole statement passes
// the same check the wrap path runs.
func TestAccountKeyTrustFixture_SignaturesVerify(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	verify := func(t *testing.T, pemStr, sigB64 string) error {
		t.Helper()
		key, err := crypto.ParsePublicKey(pemStr)
		if err != nil {
			t.Fatalf("parse public key: %v", err)
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		return crypto.VerifySignature(key, fixture.CanonicalUTF8, sig)
	}

	if err := verify(t, fixture.OldPublicKeyPEM, fixture.OldSignatureB64); err != nil {
		t.Fatalf("old_signature_b64 does not verify: %v", err)
	}
	if err := verify(t, fixture.NewPublicKeyPEM, fixture.NewSignatureB64); err != nil {
		t.Fatalf("new_signature_b64 does not verify: %v", err)
	}

	// The wrong-signer vector must fail against the key it claims.
	if err := verify(t, fixture.NewPublicKeyPEM, fixture.NegativeWrongSigner.NewSignatureB64); err == nil {
		t.Fatal("negative_wrong_signer verified against new_public_key_pem")
	}
	// It is a real signature, just by the wrong key.
	if err := verify(t, fixture.NegativeWrongSigner.WrongSignerPublicKeyPEM,
		fixture.NegativeWrongSigner.NewSignatureB64); err != nil {
		t.Fatalf("negative_wrong_signer is not a valid signature by its own signer: %v", err)
	}
}

// The broken-chain vector is internally sound and still does not link: every
// signature verifies, but it starts somewhere a pin on old_fingerprint has
// never been.
func TestAccountKeyTrustFixture_BrokenChainDoesNotLink(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)
	statement := fixture.NegativeBrokenChain.Statement

	if err := statement.Validate(); err != nil {
		t.Fatalf("broken-chain statement is not even structurally valid: %v", err)
	}
	if statement.Canonical() != fixture.NegativeBrokenChain.CanonicalUTF8 {
		t.Fatalf("broken-chain canonical = %q, want %q",
			statement.Canonical(), fixture.NegativeBrokenChain.CanonicalUTF8)
	}
	if statement.OldFingerprint == fixture.OldFingerprint {
		t.Fatal("broken-chain statement starts at the pinned fingerprint; it would link")
	}
	if statement.NewFingerprint != fixture.NewFingerprint {
		t.Fatal("broken-chain statement does not end at the observed key; " +
			"the vector should isolate the start, not both ends")
	}

	// Its own signatures are genuine, so what fails is the linkage alone.
	oldKey, err := base64.StdEncoding.DecodeString(statement.OldPublicKey)
	if err != nil {
		t.Fatalf("decode broken-chain old_public_key: %v", err)
	}
	if crypto.AccountKeyFingerprint(oldKey) != statement.OldFingerprint {
		t.Fatal("broken-chain old_fingerprint does not hash its own key")
	}
}

// The pin record's serialization and its size, which is what the per-entry
// keyring limit is measured against.
func TestAccountKeyTrustFixture_PinRecord(t *testing.T) {
	fixture := loadAccountKeyTrustFixture(t)

	if got := len(fixture.PinRecordJSON.JSON); got != fixture.PinRecordJSON.ByteLength {
		t.Fatalf("pin_record_json byte_length = %d, actual %d", fixture.PinRecordJSON.ByteLength, got)
	}
	if fixture.PinRecordJSON.ByteLength >= keychain.PeerKeyPinMaxItemBytes {
		t.Fatalf("pin record is %d bytes, want under %d",
			fixture.PinRecordJSON.ByteLength, keychain.PeerKeyPinMaxItemBytes)
	}

	var pin keychain.PeerKeyPin
	if err := json.Unmarshal([]byte(fixture.PinRecordJSON.JSON), &pin); err != nil {
		t.Fatalf("decode pin_record_json: %v", err)
	}
	if pin.V != keychain.PeerKeyPinVersion {
		t.Fatalf("pin record v = %d, want %d", pin.V, keychain.PeerKeyPinVersion)
	}
	if pin.Fingerprint != fixture.NewFingerprint || pin.LastRotationFingerprint != fixture.OldFingerprint {
		t.Fatalf("pin record fingerprints = %q / %q, want the fixture's new / old",
			pin.Fingerprint, pin.LastRotationFingerprint)
	}

	// Re-marshalling must reproduce the fixture byte for byte, or the TS side
	// is being handed a shape this code no longer writes.
	remarshalled, err := json.Marshal(pin)
	if err != nil {
		t.Fatalf("marshal pin record: %v", err)
	}
	if string(remarshalled) != fixture.PinRecordJSON.JSON {
		t.Fatalf("pin record round trip changed the bytes:\n got %s\nwant %s",
			remarshalled, fixture.PinRecordJSON.JSON)
	}
}
