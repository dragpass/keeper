// shamir.go — Shamir Secret Sharing over GF(2^8), in-repo implementation.
//
// Splits a byte secret (here: the org archive RSA private key PEM) into M
// shares such that any N of them reconstruct the secret and any N-1 reveal
// nothing. Standard construction: for each secret byte, a random degree-(N-1)
// polynomial whose constant term is that byte, evaluated at x = 1..M; recovery
// is Lagrange interpolation at x = 0. Arithmetic is in GF(2^8) with the AES
// reduction polynomial 0x11b (x^8 + x^4 + x^3 + x + 1).
//
// No external dependency is pulled in for this — the field is small and the
// algorithm is well specified, so a vendored ~150-line implementation avoids
// the license / supply-chain surface of a third-party lib. Determinism is
// verified by shamir_test.go against fixed vectors.
//
// A Share carries its x-coordinate (1..255) alongside the per-byte y values,
// so the caller does not have to track indices separately for recovery.

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
)

// gfExp / gfLog are the exp/log tables for GF(2^8) with generator 0x03 under
// the AES field polynomial 0x11b. Built once at package init.
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := byte(1)
	for i := range 255 {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// multiply x by the generator 0x03 in GF(2^8): x*3 = x*2 ^ x.
		x = gfMulNoTable(x, 0x03)
	}
	// Duplicate the exp table so index arithmetic (log_a + log_b) up to 510
	// never needs a modulo.
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMulNoTable multiplies two GF(2^8) elements via Russian-peasant / carryless
// multiply with reduction by 0x11b. Used only to bootstrap the tables at init.
func gfMulNoTable(a, b byte) byte {
	var p byte
	for range 8 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // 0x11b mod 0x100 (implicit high bit already shifted out)
		}
		b >>= 1
	}
	return p
}

// gfMul multiplies two field elements via the log/exp tables.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfDiv divides a by b (b != 0) in the field.
func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	// log(a) - log(b) mod 255, kept non-negative by adding 255.
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

// Share is one Shamir share: an x-coordinate (1..255) and the polynomial
// evaluations at that x for each secret byte.
type Share struct {
	X byte
	Y []byte
}

// SplitSecret splits secret into total shares with threshold reconstruction.
//
//   - threshold: the N in "N-of-M" — how many shares reconstruct the secret.
//   - total: the M — how many shares to produce (x = 1..total).
//
// Requires 2 <= threshold <= total <= 255 and a non-empty secret.
func SplitSecret(secret []byte, threshold, total int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: secret is empty")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("shamir: threshold must be >= 2, got %d", threshold)
	}
	if total < threshold {
		return nil, fmt.Errorf("shamir: total (%d) < threshold (%d)", total, threshold)
	}
	if total > 255 {
		return nil, fmt.Errorf("shamir: total must be <= 255, got %d", total)
	}

	shares := make([]Share, total)
	for i := range total {
		shares[i] = Share{X: byte(i + 1), Y: make([]byte, len(secret))}
	}

	// One random polynomial per secret byte. coeffs[0] is the secret byte;
	// coeffs[1..threshold-1] are uniformly random.
	coeffs := make([]byte, threshold)
	for b := range secret {
		coeffs[0] = secret[b]
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: rand read: %w", err)
		}
		for i := range total {
			shares[i].Y[b] = evalPoly(coeffs, shares[i].X)
		}
	}
	return shares, nil
}

// evalPoly evaluates the polynomial with the given coefficients (ascending
// degree) at x using Horner's method in GF(2^8).
func evalPoly(coeffs []byte, x byte) byte {
	var y byte
	for _, coeff := range slices.Backward(coeffs) {
		y = gfMul(y, x) ^ coeff
	}
	return y
}

// CombineShares reconstructs the secret from shares via Lagrange interpolation
// at x = 0. It requires at least 2 shares with distinct, non-zero x-coordinates
// and equal-length y vectors. Supplying fewer than the original threshold, or
// tampered shares, returns a well-formed but wrong secret (Shamir gives no
// integrity by itself — the caller detects a bad reconstruction downstream,
// e.g. the reassembled key fails to parse / decrypt).
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least 2 shares to combine")
	}
	length := len(shares[0].Y)
	if length == 0 {
		return nil, errors.New("shamir: empty share")
	}
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if s.X == 0 {
			return nil, errors.New("shamir: share x-coordinate must be non-zero")
		}
		if seen[s.X] {
			return nil, fmt.Errorf("shamir: duplicate share x-coordinate %d", s.X)
		}
		seen[s.X] = true
		if len(s.Y) != length {
			return nil, errors.New("shamir: shares have differing lengths")
		}
	}

	secret := make([]byte, length)
	for b := range length {
		var acc byte
		for i := range shares {
			// Lagrange basis L_i(0) = Π_{j≠i} x_j / (x_j - x_i), evaluated in
			// GF(2^8) where subtraction is XOR.
			num := byte(1)
			den := byte(1)
			for j := range shares {
				if i == j {
					continue
				}
				num = gfMul(num, shares[j].X)
				den = gfMul(den, shares[i].X^shares[j].X)
			}
			acc ^= gfMul(shares[i].Y[b], gfDiv(num, den))
		}
		secret[b] = acc
	}
	return secret, nil
}

// SerializeShare packs a share as x || y for wrapping/transport. The inverse is
// DeserializeShare. The x-coordinate travels inside the (later authenticated)
// payload so a reconstruction cannot be silently fed a wrong index.
func SerializeShare(s Share) []byte {
	out := make([]byte, 0, 1+len(s.Y))
	out = append(out, s.X)
	out = append(out, s.Y...)
	return out
}

// DeserializeShare reverses SerializeShare.
func DeserializeShare(b []byte) (Share, error) {
	if len(b) < 2 {
		return Share{}, errors.New("shamir: serialized share too short")
	}
	if b[0] == 0 {
		return Share{}, errors.New("shamir: serialized share has zero x-coordinate")
	}
	y := make([]byte, len(b)-1)
	copy(y, b[1:])
	return Share{X: b[0], Y: y}, nil
}
