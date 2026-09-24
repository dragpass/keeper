package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const (
	snA  = "a1111111-1111-4111-8111-111111111111"
	snB  = "b2222222-2222-4222-8222-222222222222"
	snFA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	snFB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// The value is SHA-256 over the domain and the pairs sorted by account id,
// the same from either side, and the digits are that value mod 10^60,
// zero-padded. This pins the bytes the contract names.
func TestSafetyNumber_IsTheContractValueFromEitherSide(t *testing.T) {
	value, digits := safetyNumber(snA, snFA, snB, snFB)
	back, backDigits := safetyNumber(snB, snFB, snA, snFA)
	if hex.EncodeToString(value) != hex.EncodeToString(back) || digits != backDigits {
		t.Fatal("the two sides of the pair compute different numbers")
	}
	want := sha256.Sum256([]byte("dragpass.safety_number|1|" + snA + "|" + snFA + "|" + snB + "|" + snFB))
	if hex.EncodeToString(value) != hex.EncodeToString(want[:]) {
		t.Fatalf("value = %x; want %x", value, want)
	}
	n := new(big.Int).Mod(new(big.Int).SetBytes(want[:]), new(big.Int).Exp(big.NewInt(10), big.NewInt(60), nil))
	if len(digits) != 60 || strings.TrimLeft(digits, "0") != n.String() {
		t.Fatalf("digits = %q; want %s padded to 60", digits, n.String())
	}
	if _, other := safetyNumber(snA, snFB, snB, snFB); other == digits {
		t.Fatal("another key gives the same number")
	}
}
