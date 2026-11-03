// credential_reseal.go — the credential payload a tracked encrypt reseals
// (lv84).
//
// A credential DragLink carries its secret twice: in the drag token people
// edit and in the sealed payload MCP injects. When the value changes, the
// payload is resealed in the same call that seals the token, from the same
// plaintext, so the two cannot hold different values. The value never leaves
// Keeper; only the sealed bytes do. See docs/protocol.md "Credential payload
// reseal".

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// The payload shape the Extension's auto-prepare writes, the only client
// producer of a credential payload. Field order matches JSON.stringify there.
const (
	credentialPayloadPrefix = `{"type":"api_key","secret":{"authorization_scheme":"Bearer","token":"`
	credentialPayloadSuffix = `"}}`
)

// credentialPayloadJSON builds the payload around value without converting it
// to a Go string, so the only copies are byte slices the caller zeroizes. It
// returns nil when value is not valid UTF-8: JSON would have to replace bytes
// and the payload would hold a different value than the token.
func credentialPayloadJSON(value []byte) []byte {
	if !utf8.Valid(value) {
		return nil
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(credentialPayloadPrefix)+2*len(value)+len(credentialPayloadSuffix))
	out = append(out, credentialPayloadPrefix...)
	for _, b := range value {
		switch {
		case b == '"' || b == '\\':
			out = append(out, '\\', b)
		case b < 0x20:
			out = append(out, '\\', 'u', '0', '0', hex[b>>4], hex[b&0xf])
		default:
			out = append(out, b)
		}
	}
	return append(out, credentialPayloadSuffix...)
}

// resealCredentialPayload seals value as a credential payload under dek and
// the canonical AAD. A value that cannot be carried, or a sealing failure,
// yields nil: the reseal is a by-product and never blocks the token.
func resealCredentialPayload(random io.Reader, dek []byte, scopeID, entryID string, dekVersion int, value []byte) *proto.CredentialPayloadSealed {
	payload := credentialPayloadJSON(value)
	if payload == nil {
		return nil
	}
	defer secure.Zeroize(payload)
	aad := []byte(proto.CredentialPayloadAAD(scopeID, entryID, dekVersion))
	iv, ciphertext, err := crypto.SealAESGCM(random, dek, payload, aad)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(aad)
	return &proto.CredentialPayloadSealed{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		DekVersion:    dekVersion,
		AADHashB64:    base64.StdEncoding.EncodeToString(sum[:]),
	}
}
