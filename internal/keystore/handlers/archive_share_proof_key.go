package handlers

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// deriveArchiveShareProofKey derives the per-share Ed25519 proof key from the
// serialized share (x || y, as wrapped at split). Only the holder of the
// share can re-derive the private key, so a signature with it proves the
// share was opened. The HKDF seed is zeroized here; the caller zeroizes the
// returned private key.
func deriveArchiveShareProofKey(serializedShare []byte, operationID string, shareIndex int) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, serializedShare, nil,
		proto.ArchiveShareProofKeyInfo(operationID, shareIndex), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer secure.Zeroize(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// archiveShareProofPublicKey returns only the Base64 public half.
func archiveShareProofPublicKey(serializedShare []byte, operationID string, shareIndex int) (string, error) {
	priv, err := deriveArchiveShareProofKey(serializedShare, operationID, shareIndex)
	if err != nil {
		return "", err
	}
	defer secure.Zeroize(priv)
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}
