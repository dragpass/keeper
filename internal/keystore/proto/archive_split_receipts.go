package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"strconv"
)

// Archive split journal states reported by archive_split_status.
const (
	ArchiveSplitStateNone           = "none"
	ArchiveSplitStatePrepared       = "prepared"
	ArchiveSplitStateDeleting       = "deleting"
	ArchiveSplitStateCleanupPending = "cleanup_pending"
	ArchiveSplitStateFinalized      = "finalized"
)

// ArchiveSplitSharesDigest commits the ordered share set the server stored:
// share index, share envelope digest and proof public key of every share.
func ArchiveSplitSharesDigest(shares []WrappedShare) string {
	fields := []string{strconv.Itoa(len(shares))}
	for _, s := range shares {
		fields = append(fields, strconv.Itoa(s.ShareIndex),
			ArchiveShareEnvelopeDigest(s.ShareIndex, s.WrappedKey, s.Ciphertext), s.ProofPublicKey)
	}
	sum := sha256.Sum256([]byte(archiveShareCanonical("dragpass.archive.split.shares|1", fields...)))
	return hex.EncodeToString(sum[:])
}

// ArchiveSplitFinalizationReceipt is the server's signed statement that it
// committed the exact share set and the share-open proofs for an operation
// and activated the quorum configuration. It has no expiry: Keeper accepts
// it only against its own split journal and current archive key.
type ArchiveSplitFinalizationReceipt struct {
	OperationID               string `json:"operation_id"`
	OrgID                     string `json:"org_id"`
	ArchiveKeySPKIFingerprint string `json:"archive_key_spki_fingerprint"`
	ConfigDigest              string `json:"config_digest"`
	SharesDigest              string `json:"shares_digest"`
	FinalizedAt               int64  `json:"finalized_at"`
	ServerKeyVersion          uint   `json:"server_key_version"`
	Signature                 string `json:"signature"`
}

func ArchiveSplitFinalizationReceiptCanonical(r ArchiveSplitFinalizationReceipt) string {
	return archiveShareCanonical("dragpass.archive.split.finalized|1", r.OperationID, r.OrgID,
		r.ArchiveKeySPKIFingerprint, r.ConfigDigest, r.SharesDigest, strconv.FormatInt(r.FinalizedAt, 10),
		strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
}

func (r ArchiveSplitFinalizationReceipt) Validate() error {
	for _, id := range []string{r.OperationID, r.OrgID} {
		if err := requireMessageUUID(id, "receipt.identity"); err != nil {
			return err
		}
	}
	for _, digest := range []string{r.ArchiveKeySPKIFingerprint, r.ConfigDigest, r.SharesDigest} {
		if err := requireMessageDigest(digest, "receipt.digest"); err != nil {
			return err
		}
	}
	if r.FinalizedAt <= 0 {
		return newValidationError("receipt.finalized_at", "must be positive")
	}
	return validateArchiveReceiptSignature(r.ServerKeyVersion, r.Signature)
}

// Closure statuses a closure receipt may carry.
const (
	ArchiveSplitClosedCancelled   = "cancelled"
	ArchiveSplitClosedExpired     = "expired"
	ArchiveSplitClosedInvalidated = "invalidated"
)

// ArchiveSplitClosureReceipt is the server's signed statement that a split
// operation ended without finalization. Keeper then drops its journal and
// keeps the archive private key.
type ArchiveSplitClosureReceipt struct {
	OperationID               string `json:"operation_id"`
	OrgID                     string `json:"org_id"`
	Status                    string `json:"status"`
	ArchiveKeySPKIFingerprint string `json:"archive_key_spki_fingerprint"`
	ServerKeyVersion          uint   `json:"server_key_version"`
	Signature                 string `json:"signature"`
}

func ArchiveSplitClosureReceiptCanonical(r ArchiveSplitClosureReceipt) string {
	return archiveShareCanonical("dragpass.archive.split.closed|1", r.OperationID, r.OrgID, r.Status,
		r.ArchiveKeySPKIFingerprint, strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
}

func (r ArchiveSplitClosureReceipt) Validate() error {
	for _, id := range []string{r.OperationID, r.OrgID} {
		if err := requireMessageUUID(id, "receipt.identity"); err != nil {
			return err
		}
	}
	switch r.Status {
	case ArchiveSplitClosedCancelled, ArchiveSplitClosedExpired, ArchiveSplitClosedInvalidated:
	default:
		return newValidationError("receipt.status", "must be cancelled, expired or invalidated")
	}
	if err := requireMessageDigest(r.ArchiveKeySPKIFingerprint, "receipt.archive_key_spki_fingerprint"); err != nil {
		return err
	}
	return validateArchiveReceiptSignature(r.ServerKeyVersion, r.Signature)
}

type ArchiveSplitFinalizeRequest struct {
	OrgID   string                           `json:"org_id"`
	Receipt *ArchiveSplitFinalizationReceipt `json:"receipt,omitempty"`
}

type ArchiveSplitAbandonRequest struct {
	OrgID   string                      `json:"org_id"`
	Receipt *ArchiveSplitClosureReceipt `json:"receipt,omitempty"`
}

type ArchiveSplitStatusRequest struct {
	OrgID string `json:"org_id"`
}

// ArchiveSplitStateResponseData names the journal state and its operation
// only; it never carries shares, keys or receipts.
type ArchiveSplitStateResponseData struct {
	State       string `json:"state"`
	OperationID string `json:"operation_id,omitempty"`
}

func validateArchiveReceiptSignature(version uint, signature string) error {
	if version == 0 || version > math.MaxUint32 {
		return newValidationError("receipt.server_key_version", "invalid version")
	}
	if b, err := base64.StdEncoding.DecodeString(signature); err != nil || len(b) == 0 {
		return newValidationError("receipt.signature", "invalid signature")
	}
	return nil
}

func (r ArchiveSplitStatusRequest) Validate() error {
	return requireMessageUUID(r.OrgID, "org_id")
}

func (r ArchiveSplitFinalizeRequest) Validate() error {
	if r.Receipt == nil {
		return newValidationError("receipt", "required")
	}
	if err := r.Receipt.Validate(); err != nil {
		return err
	}
	if r.OrgID != r.Receipt.OrgID {
		return newValidationError("org_id", "must equal receipt.org_id")
	}
	return nil
}

func (r ArchiveSplitAbandonRequest) Validate() error {
	if r.Receipt == nil {
		return newValidationError("receipt", "required")
	}
	if err := r.Receipt.Validate(); err != nil {
		return err
	}
	if r.OrgID != r.Receipt.OrgID {
		return newValidationError("org_id", "must equal receipt.org_id")
	}
	return nil
}
