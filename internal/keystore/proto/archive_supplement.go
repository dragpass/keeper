package proto

import "strconv"

type SupplementPrevious struct {
	OrgID             string `json:"org_id"`
	OperationID       string `json:"operation_id"`
	ConfigDigest      string `json:"config_digest"`
	PreviousSessionID string `json:"previous_session_id"`
	PreviousSPKI      string `json:"previous_session_key_spki_fingerprint"`
}

func (r SupplementPrevious) Validate() error {
	for _, id := range []string{r.OrgID, r.OperationID, r.PreviousSessionID} {
		if err := requireMessageUUID(id, "session.identity"); err != nil {
			return err
		}
	}
	for _, digest := range []string{r.ConfigDigest, r.PreviousSPKI} {
		if err := requireMessageDigest(digest, "session.digest"); err != nil {
			return err
		}
	}
	return nil
}

type SupplementPrepare struct {
	ArchiveLoginScope
	SupplementPrevious
	PreviousRound int `json:"previous_session_round"`
}

func (r SupplementPrepare) Validate() error {
	if r.PreviousRound < 0 {
		return newValidationError("previous_session_round", "must be nonnegative")
	}
	return r.SupplementPrevious.Validate()
}

type SupplementCandidate struct {
	PublicKey string `json:"session_public_key"`
	SPKI      string `json:"session_key_spki_fingerprint"`
}
type SupplementReceipt struct {
	SupplementPrevious
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	SPKI      string `json:"session_key_spki_fingerprint"`
	Round     int    `json:"session_round"`
	ExpiresAt int64  `json:"expires_at"`
	Version   uint   `json:"server_key_version"`
	Signature string `json:"signature"`
}

func (r SupplementReceipt) Canonical() string {
	return archiveShareCanonical("dragpass.archive.reconfiguration.supplement.accepted|1", r.OrgID, r.OperationID, r.ConfigDigest, r.AccountID, r.DeviceID, r.PreviousSessionID, r.PreviousSPKI, r.SessionID, r.SPKI, strconv.Itoa(r.Round), strconv.FormatInt(r.ExpiresAt, 10), strconv.FormatUint(uint64(r.Version), 10))
}

type SupplementPromote struct {
	ArchiveLoginScope
	Receipt SupplementReceipt `json:"acceptance_receipt"`
}

func (r SupplementPromote) Validate() error {
	a := r.Receipt
	if a.SessionID == a.PreviousSessionID || a.SPKI == a.PreviousSPKI || a.Round < 1 || a.ExpiresAt <= 0 || a.Version == 0 || a.Signature == "" {
		return newValidationError("acceptance_receipt", "invalid acceptance")
	}
	for _, id := range []string{a.AccountID, a.DeviceID, a.SessionID} {
		if err := requireMessageUUID(id, "acceptance_receipt.identity"); err != nil {
			return err
		}
	}
	if err := requireMessageDigest(a.SPKI, "acceptance_receipt.session_key_spki_fingerprint"); err != nil {
		return err
	}
	return a.SupplementPrevious.Validate()
}

type SupplementPromoted struct {
	SessionID string `json:"session_id"`
	Round     int    `json:"session_round"`
	SPKI      string `json:"session_key_spki_fingerprint"`
}

type SupplementDamage struct {
	State        string `json:"state"`
	StoredDigest string `json:"stored_digest,omitempty"`
}

type SupplementDiscard struct {
	SupplementPrepare
	StoredDigest string `json:"stored_digest"`
	Confirm      bool   `json:"confirm"`
}

func (r SupplementDiscard) Validate() error {
	if !r.Confirm {
		return newValidationError("confirm", "explicit confirmation required")
	}
	if err := requireMessageDigest(r.StoredDigest, "stored_digest"); err != nil {
		return err
	}
	return r.SupplementPrepare.Validate()
}
