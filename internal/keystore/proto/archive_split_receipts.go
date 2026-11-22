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
	Kind                      string `json:"kind,omitempty"`
	TargetKeySPKIFingerprint  string `json:"target_key_spki_fingerprint,omitempty"`
	SourceConfigDigest        string `json:"source_config_digest,omitempty"`
	GrantsDigest              string `json:"grants_digest,omitempty"`
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
	if r.Kind == "reconfiguration" {
		return archiveShareCanonical("dragpass.archive.split.finalized|2", r.Kind, r.OperationID, r.OrgID, r.ArchiveKeySPKIFingerprint, r.TargetKeySPKIFingerprint, r.SourceConfigDigest, r.ConfigDigest, r.SharesDigest, r.GrantsDigest, strconv.FormatInt(r.FinalizedAt, 10), strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
	}
	return archiveShareCanonical("dragpass.archive.split.finalized|1", r.OperationID, r.OrgID,
		r.ArchiveKeySPKIFingerprint, r.ConfigDigest, r.SharesDigest, strconv.FormatInt(r.FinalizedAt, 10),
		strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
}

func (r ArchiveSplitFinalizationReceipt) Validate() error {
	if r.Kind == "reconfiguration" {
		for _, v := range []string{r.TargetKeySPKIFingerprint, r.SourceConfigDigest, r.GrantsDigest} {
			if err := requireMessageDigest(v, "receipt.reconfiguration"); err != nil {
				return err
			}
		}
		if r.TargetKeySPKIFingerprint == r.ArchiveKeySPKIFingerprint {
			return newValidationError("receipt.target", "must differ from source")
		}
	} else if r.Kind != "" || r.TargetKeySPKIFingerprint != "" || r.SourceConfigDigest != "" || r.GrantsDigest != "" {
		return newValidationError("receipt.kind", "invalid finalization binding")
	}
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
	Kind                      string `json:"kind,omitempty"`
	SourceConfigDigest        string `json:"source_config_digest,omitempty"`
	TargetKeySPKIFingerprint  string `json:"target_key_spki_fingerprint,omitempty"`
	OperationID               string `json:"operation_id"`
	OrgID                     string `json:"org_id"`
	Status                    string `json:"status"`
	ArchiveKeySPKIFingerprint string `json:"archive_key_spki_fingerprint"`
	ServerKeyVersion          uint   `json:"server_key_version"`
	Signature                 string `json:"signature"`
}

func ArchiveSplitClosureReceiptCanonical(r ArchiveSplitClosureReceipt) string {
	if r.Kind == "reconfiguration" {
		return archiveShareCanonical("dragpass.archive.split.closed|2", r.Kind, r.OperationID, r.OrgID, r.Status, r.TargetKeySPKIFingerprint, r.SourceConfigDigest, strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
	}
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
	if r.Kind == "reconfiguration" {
		if r.ArchiveKeySPKIFingerprint != "" {
			return newValidationError("receipt.archive_key_spki_fingerprint", "unexpected activation key")
		}
		for _, digest := range []string{r.SourceConfigDigest, r.TargetKeySPKIFingerprint} {
			if err := requireMessageDigest(digest, "receipt.digest"); err != nil {
				return err
			}
		}
		return validateArchiveReceiptSignature(r.ServerKeyVersion, r.Signature)
	}
	if r.Kind != "" || r.SourceConfigDigest != "" || r.TargetKeySPKIFingerprint != "" {
		return newValidationError("receipt.kind", "invalid closure binding")
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

type ArchiveUnregisteredClosure struct {
	OperationID        string `json:"operation_id"`
	OrgID              string `json:"org_id"`
	RequesterAccountID string `json:"requester_account_id"`
	RequesterDeviceID  string `json:"requester_device_id"`
	SourceConfigDigest string `json:"source_config_digest"`
	Status             string `json:"status"`
	ServerKeyVersion   uint   `json:"server_key_version"`
	Signature          string `json:"signature"`
}

func (r ArchiveUnregisteredClosure) Canonical() string {
	return archiveShareCanonical("dragpass.archive.reconfiguration.closed-unregistered|1", r.OperationID, r.OrgID, r.RequesterAccountID, r.RequesterDeviceID, r.SourceConfigDigest, r.Status, strconv.FormatUint(uint64(r.ServerKeyVersion), 10))
}

func (r ArchiveUnregisteredClosure) Validate() error {
	for _, id := range []string{r.OperationID, r.OrgID, r.RequesterAccountID, r.RequesterDeviceID} {
		if err := requireMessageUUID(id, "closure.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(r.SourceConfigDigest, "closure.source_config_digest"); err != nil {
		return err
	}
	switch r.Status {
	case ArchiveSplitClosedCancelled, ArchiveSplitClosedExpired, ArchiveSplitClosedInvalidated:
	default:
		return newValidationError("closure.status", "invalid terminal status")
	}
	return validateArchiveReceiptSignature(r.ServerKeyVersion, r.Signature)
}

type ArchiveSplitAbandonRequest struct {
	ExpectedLoginGeneration string                      `json:"expected_login_generation,omitempty"`
	UnregisteredClosure     *ArchiveUnregisteredClosure `json:"unregistered_closure,omitempty"`
	Confirmed               bool                        `json:"confirmed,omitempty"`
	ExpectedFingerprint     string                      `json:"expected_fingerprint,omitempty"`
	OrgID                   string                      `json:"org_id"`
	Receipt                 *ArchiveSplitClosureReceipt `json:"receipt,omitempty"`
}

type ArchiveSplitStatusRequest struct {
	Kind  string `json:"kind,omitempty"`
	OrgID string `json:"org_id"`
}

// ArchiveSplitStateResponseData names the journal state and its operation
// only; it never carries shares, keys or receipts.
type ArchiveSplitStateResponseData struct {
	LoginGeneration string `json:"login_generation,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	State           string `json:"state"`
	OperationID     string `json:"operation_id,omitempty"`
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
	if r.Kind != "" && r.Kind != "activation" && r.Kind != "reconfiguration" {
		return newValidationError("kind", "unsupported operation kind")
	}
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
	if c := r.UnregisteredClosure; c != nil {
		if r.Receipt != nil || !r.Confirmed || r.OrgID != c.OrgID {
			return newValidationError("unregistered_closure", "requires matching organization and explicit confirmation")
		}
		if err := requireMessageDigest(r.ExpectedFingerprint, "expected_fingerprint"); err != nil {
			return err
		}
		if err := (ArchiveLoginIdentity{AccountID: c.RequesterAccountID, Generation: r.ExpectedLoginGeneration}).Validate(); err != nil {
			return err
		}
		return c.Validate()
	}
	if r.ExpectedLoginGeneration != "" || r.ExpectedFingerprint != "" || r.Confirmed {
		return newValidationError("unregistered_closure", "missing confirmed closure")
	}
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
