package proto

import (
	"encoding/base64"
	"errors"
)

// SplitMetaCipherInline splits Base64(IV(12)||ciphertext) metadata.
func SplitMetaCipherInline(encoded string) ([]byte, []byte, error) {
	if encoded == "" {
		return nil, nil, errors.New("meta cipher empty")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, errors.New("meta cipher base64 decode: " + err.Error())
	}
	if len(raw) < 12 {
		return nil, nil, errors.New("meta cipher too short (< 12B IV)")
	}
	return raw[:12], raw[12:], nil
}
