package crypto

import (
	"bytes"
	"testing"
)

// TestGFMul_KnownVector locks the field arithmetic to the AES GF(2^8) field:
// 0x53 and 0xCA are multiplicative inverses (0x53 * 0xCA = 0x01), a standard
// AES S-box worked example.
func TestGFMul_KnownVector(t *testing.T) {
	if got := gfMul(0x53, 0xCA); got != 0x01 {
		t.Fatalf("gfMul(0x53,0xCA) = %#x, want 0x01", got)
	}
	if got := gfMul(0x57, 0x83); got != 0xc1 {
		t.Fatalf("gfMul(0x57,0x83) = %#x, want 0xc1", got)
	}
	if got := gfDiv(0x01, 0x53); got != 0xCA {
		t.Fatalf("gfDiv(0x01,0x53) = %#x, want 0xca", got)
	}
}

// TestCombineShares_DeterministicVector locks CombineShares against a
// hand-computed 2-of-N split of secret byte 0x53 with degree-1 coefficient
// 0xAA: poly(x) = 0x53 ^ gfMul(0xAA, x). poly(1)=0xF9, poly(2)=0x1C.
func TestCombineShares_DeterministicVector(t *testing.T) {
	shares := []Share{
		{X: 1, Y: []byte{0xF9}},
		{X: 2, Y: []byte{0x1C}},
	}
	got, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(got, []byte{0x53}) {
		t.Fatalf("reconstructed = %#x, want 0x53", got)
	}
}

// TestSplitCombine_RoundTrip verifies every N-subset of the M shares
// reconstructs the original secret.
func TestSplitCombine_RoundTrip(t *testing.T) {
	secret := []byte("the-quick-brown-fox-archive-private-key-PEM-stand-in-\x00\x01\xff")
	const threshold, total = 3, 5

	shares, err := SplitSecret(secret, threshold, total)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	if len(shares) != total {
		t.Fatalf("got %d shares, want %d", len(shares), total)
	}

	// Every combination of exactly `threshold` shares must reconstruct.
	var pick func(start, need int, acc []Share)
	pick = func(start, need int, acc []Share) {
		if need == 0 {
			got, err := CombineShares(acc)
			if err != nil {
				t.Fatalf("CombineShares subset: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("subset reconstruct mismatch: got %q", got)
			}
			return
		}
		for i := start; i <= len(shares)-need; i++ {
			pick(i+1, need-1, append(acc, shares[i]))
		}
	}
	pick(0, threshold, nil)

	// All M shares together also reconstruct.
	got, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares all: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("all-shares reconstruct mismatch")
	}
}

// TestCombineShares_BelowThresholdFails confirms that fewer than `threshold`
// shares do not reconstruct the secret. Shamir provides no integrity, so the
// result is a well-formed but wrong secret rather than an error.
func TestCombineShares_BelowThresholdFails(t *testing.T) {
	secret := []byte("recover-me-fully-or-not-at-all-0123456789")
	const threshold, total = 3, 5

	shares, err := SplitSecret(secret, threshold, total)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// threshold-1 = 2 shares must NOT yield the secret.
	got, err := CombineShares(shares[:threshold-1])
	if err != nil {
		t.Fatalf("CombineShares (below threshold) unexpected error: %v", err)
	}
	if bytes.Equal(got, secret) {
		t.Fatalf("below-threshold combine reconstructed the secret; leak")
	}
}

func TestSerializeDeserializeShare(t *testing.T) {
	s := Share{X: 42, Y: []byte{0x00, 0x11, 0x22, 0xff}}
	round, err := DeserializeShare(SerializeShare(s))
	if err != nil {
		t.Fatalf("DeserializeShare: %v", err)
	}
	if round.X != s.X || !bytes.Equal(round.Y, s.Y) {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", round, s)
	}
	if _, err := DeserializeShare([]byte{0x01}); err == nil {
		t.Fatalf("expected error for too-short serialized share")
	}
	if _, err := DeserializeShare([]byte{0x00, 0x11}); err == nil {
		t.Fatalf("expected error for zero x-coordinate")
	}
}

func TestSplitSecret_Validation(t *testing.T) {
	cases := []struct {
		name             string
		secret           []byte
		threshold, total int
	}{
		{"empty secret", nil, 2, 3},
		{"threshold too low", []byte("x"), 1, 3},
		{"total below threshold", []byte("x"), 3, 2},
		{"total too high", []byte("x"), 2, 256},
	}
	for _, c := range cases {
		if _, err := SplitSecret(c.secret, c.threshold, c.total); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}
