package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
)

// ArchiveShareOpenProofRequest asks a participant Keeper to open its own
// share and prove it by signing with the share-derived proof key. The share
// plaintext and the derived private key never leave Keeper.
type ArchiveShareOpenProofRequest struct {
	AccountID      string                         `json:"account_id"`
	OrgID          string                         `json:"org_id"`
	OperationID    string                         `json:"operation_id"`
	ConfigDigest   string                         `json:"config_digest"`
	ShareIndex     int                            `json:"share_index"`
	WrappedKey     string                         `json:"wrapped_key"`
	Ciphertext     string                         `json:"ciphertext"`
	ProofPublicKey string                         `json:"proof_public_key"`
	Decision       *ArchiveShareOpenProofDecision `json:"decision,omitempty"`
}

func (r ArchiveShareOpenProofRequest) Validate() error {
	for _, id := range []string{r.AccountID, r.OrgID, r.OperationID} {
		if err := requireMessageUUID(id, "request.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(r.ConfigDigest, "config_digest"); err != nil {
		return err
	}
	if r.ShareIndex < 1 || r.ShareIndex > 255 {
		return newValidationError("share_index", "must be within 1..255")
	}
	if _, err := requireBase64(r.WrappedKey, "wrapped_key"); err != nil {
		return err
	}
	if _, err := requireBase64(r.Ciphertext, "ciphertext"); err != nil {
		return err
	}
	return validateProofPublicKey(r.ProofPublicKey, "proof_public_key")
}

// ArchiveShareEnvelopeDigest is the share digest both sides bind: SHA-256 of
// the length-prefixed share index and hybrid envelope fields, not of any JSON
// serialization of them.
func ArchiveShareEnvelopeDigest(shareIndex int, wrappedKey, ciphertext string) string {
	sum := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.share.envelope|1",
		strconv.Itoa(shareIndex), wrappedKey, ciphertext)))
	return hex.EncodeToString(sum[:])
}

// ArchiveShareOpenProofRequestDigest commits the exact proof request without
// its decision.
func ArchiveShareOpenProofRequestDigest(r ArchiveShareOpenProofRequest) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.share.open-proof.request|1",
		r.AccountID, r.OrgID, r.OperationID, r.ConfigDigest, strconv.Itoa(r.ShareIndex),
		ArchiveShareEnvelopeDigest(r.ShareIndex, r.WrappedKey, r.Ciphertext), r.ProofPublicKey)))
	return hex.EncodeToString(sum[:]), nil
}

// ArchiveShareOpenProofDecision is the server-signed share-open proof
// decision. ArchiveKeySPKIFingerprint is carried so the participant Keeper,
// which holds no copy of the organization archive key, can sign the
// statement that names it.
type ArchiveShareOpenProofDecision struct {
	Challenge                 string `json:"challenge"`
	AccountID                 string `json:"account_id"`
	DeviceID                  string `json:"device_id"`
	TokenID                   string `json:"token_id"`
	SessionIssuedAtNanos      int64  `json:"session_issued_at_nanos,string"`
	OrgID                     string `json:"org_id"`
	OperationID               string `json:"operation_id"`
	ConfigDigest              string `json:"config_digest"`
	ArchiveKeySPKIFingerprint string `json:"archive_key_spki_fingerprint"`
	PersonID                  string `json:"person_id"`
	ShareIndex                int    `json:"share_index"`
	ShareDigest               string `json:"share_digest"`
	ProofPublicKey            string `json:"proof_public_key"`
	ServerNonce               string `json:"server_nonce"`
	RequestDigest             string `json:"request_digest"`
	IssuedAt                  int64  `json:"issued_at"`
	ExpiresAt                 int64  `json:"expires_at"`
	ServerKeyVersion          uint   `json:"server_key_version"`
	Signature                 string `json:"signature"`
}

func ArchiveShareOpenProofDecisionCanonical(d ArchiveShareOpenProofDecision) string {
	return archiveShareCanonical("dragpass.archive.share.open-proof.decision|1",
		d.Challenge, d.AccountID, d.DeviceID, d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.OrgID,
		d.OperationID, d.ConfigDigest, d.ArchiveKeySPKIFingerprint, d.PersonID, strconv.Itoa(d.ShareIndex),
		d.ShareDigest, d.ProofPublicKey, d.ServerNonce, d.RequestDigest,
		strconv.FormatInt(d.IssuedAt, 10), strconv.FormatInt(d.ExpiresAt, 10),
		strconv.FormatUint(uint64(d.ServerKeyVersion), 10))
}

// ArchiveShareOpenProofStatement is the string the participant Keeper signs
// with the share-derived key. Its fields come from the verified decision.
func ArchiveShareOpenProofStatement(d ArchiveShareOpenProofDecision) string {
	return archiveShareCanonical("dragpass.archive.share.open-proof|1",
		d.ServerNonce, d.OperationID, d.ConfigDigest, d.ArchiveKeySPKIFingerprint, d.OrgID, d.PersonID,
		d.AccountID, d.DeviceID, strconv.Itoa(d.ShareIndex), d.ShareDigest, d.ProofPublicKey,
		strconv.FormatInt(d.ExpiresAt, 10))
}

func (d ArchiveShareOpenProofDecision) Validate() error {
	if err := validateArchiveChallenge(d.Challenge); err != nil {
		return err
	}
	b, err := base64.RawURLEncoding.DecodeString(d.ServerNonce)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != d.ServerNonce {
		return newValidationError("decision.server_nonce", "invalid nonce")
	}
	for _, id := range []string{d.AccountID, d.DeviceID, d.TokenID, d.OrgID, d.OperationID, d.PersonID} {
		if err := requireMessageUUID(id, "decision.identity"); err != nil {
			return err
		}
	}
	for _, digest := range []string{d.ConfigDigest, d.ArchiveKeySPKIFingerprint, d.ShareDigest, d.RequestDigest} {
		if err := requireMessageDigest(digest, "decision.digest"); err != nil {
			return err
		}
	}
	if d.ShareIndex < 1 || d.ShareIndex > 255 {
		return newValidationError("decision.share_index", "must be within 1..255")
	}
	if err := validateProofPublicKey(d.ProofPublicKey, "decision.proof_public_key"); err != nil {
		return err
	}
	return validateArchiveDecisionValidity(d.SessionIssuedAtNanos, d.IssuedAt, d.ExpiresAt, d.ServerKeyVersion, d.Signature)
}

type ArchiveShareProofPrepareRequest struct {
	Request              ArchiveShareOpenProofRequest `json:"request"`
	TokenID              string                       `json:"token_id"`
	SessionIssuedAtNanos int64                        `json:"session_issued_at_nanos,string"`
}

func (r ArchiveShareProofPrepareRequest) Validate() error {
	if _, err := ArchiveShareOpenProofRequestDigest(r.Request); err != nil {
		return err
	}
	return validateArchiveLogin(r.TokenID, r.SessionIssuedAtNanos)
}

type ArchiveShareProofPrepareResponseData struct {
	Challenge     string `json:"challenge"`
	RequestDigest string `json:"request_digest"`
}

// ArchiveShareOpenProofResponseData is the whole response: the Base64
// Ed25519 signature over ArchiveShareOpenProofStatement.
type ArchiveShareOpenProofResponseData struct {
	Signature string `json:"signature"`
}

func validateProofPublicKey(value, field string) error {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != value {
		return newValidationError(field, "must be a Base64 Ed25519 public key")
	}
	return nil
}
