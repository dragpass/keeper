// Package recoverykey implements the RK24 format and KDF contract shared with
// the DragPass clients. Secrets passed to this package remain byte slices so
// callers can keep ownership explicit and zeroize them after use.
package recoverykey

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Charset          = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	Length           = 24
	Version          = 1
	derivedKeyLength = 32
	pbkdf2Iterations = 600_000
)

func Generate(random io.Reader) ([]byte, error) {
	raw := make([]byte, Length)
	if _, err := io.ReadFull(random, raw); err != nil {
		return nil, err
	}
	defer zeroize(raw)

	formatted := make([]byte, 0, Length+5)
	for i, value := range raw {
		if i > 0 && i%4 == 0 {
			formatted = append(formatted, '-')
		}
		formatted = append(formatted, Charset[int(value)%len(Charset)])
	}
	return formatted, nil
}

func Normalize(input []byte) ([]byte, error) {
	normalized := make([]byte, 0, Length)
	for _, value := range input {
		switch value {
		case '-', ' ', '\t', '\n', '\r':
			continue
		}
		upper := byte(strings.ToUpper(string([]byte{value}))[0])
		if !strings.ContainsRune(Charset, rune(upper)) {
			zeroize(normalized)
			return nil, fmt.Errorf("recovery key contains invalid character")
		}
		normalized = append(normalized, upper)
	}
	if len(normalized) != Length {
		zeroize(normalized)
		return nil, fmt.Errorf("recovery key must be %d characters", Length)
	}
	return normalized, nil
}

func Derive(input []byte, alias string, version uint) (authSeedB64 string, wrapKey []byte, err error) {
	if alias == "" {
		return "", nil, errors.New("alias must not be empty")
	}
	if version == 0 {
		return "", nil, errors.New("recovery key version must be positive")
	}

	normalized, err := Normalize(input)
	if err != nil {
		return "", nil, err
	}
	defer zeroize(normalized)

	salt := []byte(alias)
	authSeed, err := hkdfBytes(normalized, salt, fmt.Sprintf("dragpass-recovery-auth-v%d", version))
	if err != nil {
		return "", nil, err
	}
	defer zeroize(authSeed)

	wrapSeed, err := hkdfBytes(normalized, salt, fmt.Sprintf("dragpass-recovery-wrap-v%d", version))
	if err != nil {
		return "", nil, err
	}
	defer zeroize(wrapSeed)

	wrapKey = pbkdf2.Key(wrapSeed, salt, pbkdf2Iterations, derivedKeyLength, sha256.New)
	return base64.StdEncoding.EncodeToString(authSeed), wrapKey, nil
}

func hkdfBytes(input, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, input, salt, info, derivedKeyLength)
}

func zeroize(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
