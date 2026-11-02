// change_track.go — entry value-change tracking (lv83).
//
// A tracked encrypt seals a bound drag token and, from the same plaintext, the
// entry's next comparison record (package changetrack). The response carries
// the token, the sealed record and a verdict; never the comparison key, the
// tag or the value. Contract: docs/protocol.md "Entry value-change tracking".

package proto

// Actions.
const (
	ActionGroupEncryptBoundTracked        = "group_encrypt_bound_tracked"
	ActionDEKUnwrapAndEncryptBoundTracked = "dek_unwrap_and_encrypt_bound_tracked"
)

// ChangeRecordMaxSeq keeps the sequence an exact JavaScript number.
const ChangeRecordMaxSeq = uint64(1<<53 - 1)

// changeRecordMaxCiphertextBytes — the record is 65 bytes plus the GCM tag;
// anything far larger is not a record.
const changeRecordMaxCiphertextBytes = 256

// ChangeRecord is a sealed comparison record as the server stores it. Every
// field is opaque or public context.
type ChangeRecord struct {
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
	DekVersion    int    `json:"dek_version"`
	Seq           uint64 `json:"seq"`
}

// validate checks only what the next record depends on: the version and the
// sequence. Unreadable bytes are not an error; they compare as unknown.
func (r ChangeRecord) validate() error {
	if r.DekVersion < 1 {
		return newValidationError("previous_record.dek_version", "must be >= 1")
	}
	if r.Seq < 1 || r.Seq >= ChangeRecordMaxSeq {
		return newValidationError("previous_record.seq", "must be between 1 and 2^53-2")
	}
	return nil
}

// GroupEncryptBoundTrackedRequest is GroupEncryptBoundRequest plus the entry
// and its current record. PreviousGroupHandle opens the record's DEK version
// when it differs from DekVersion; without it such a record compares as
// unknown.
type GroupEncryptBoundTrackedRequest struct {
	GroupHandle         string        `json:"group_handle"`
	OrgID               string        `json:"org_id"`
	GroupID             string        `json:"group_id"`
	DekVersion          int           `json:"dek_version"`
	TokenExpiry         string        `json:"token_expiry"`
	PlaintextB64        string        `json:"plaintext_b64"` // secret in REQUEST only; never logged
	EntryID             string        `json:"entry_id"`
	PreviousRecord      *ChangeRecord `json:"previous_record,omitempty"`
	PreviousGroupHandle string        `json:"previous_group_handle,omitempty"`
	// CompareDecision authorizes comparing against PreviousRecord (lv83 H1).
	// Without a valid one the verdict is "unknown"; the token and the next
	// record are still sealed. It is checked by the handler, not here, so a
	// malformed decision never blocks the encryption.
	CompareDecision *ChangeCompareDecision `json:"compare_decision,omitempty"`
}

// TokenContext — tracked tokens carry no audit table.
func (r GroupEncryptBoundTrackedRequest) TokenContext() GroupBoundTokenContext {
	return GroupBoundTokenContext{r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, "", r.TokenExpiry}
}

func (r GroupEncryptBoundTrackedRequest) Validate() error {
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.EntryID, "entry_id"); err != nil {
		return err
	}
	if r.PreviousGroupHandle != "" {
		if r.PreviousRecord == nil {
			return newValidationError("previous_group_handle", "requires previous_record")
		}
		if err := requireHandle(r.PreviousGroupHandle, "previous_group_handle"); err != nil {
			return err
		}
	}
	if r.PreviousRecord != nil {
		return r.PreviousRecord.validate()
	}
	return nil
}

// GroupEncryptBoundTrackedResponseData — the bound token plus the change
// verdict and the record that replaces the previous one.
type GroupEncryptBoundTrackedResponseData struct {
	IVB64         string       `json:"iv_b64"`
	CiphertextB64 string       `json:"ciphertext_b64"`
	ChangeVerdict string       `json:"change_verdict"`
	ChangeRecord  ChangeRecord `json:"change_record"`
}

// DEKUnwrapAndEncryptBoundTrackedRequest is DEKUnwrapAndEncryptBoundRequest
// plus the entry and its current record. The personal DEK has one version, so
// no second key is ever needed.
type DEKUnwrapAndEncryptBoundTrackedRequest struct {
	EncryptedDEKB64 string        `json:"encrypted_dek_b64,omitempty"` // empty: the Keeper's own slot
	TokenExpiry     string        `json:"token_expiry"`
	PlaintextB64    string        `json:"plaintext_b64"` // secret in REQUEST only; never logged
	EntryID         string        `json:"entry_id"`
	PreviousRecord  *ChangeRecord `json:"previous_record,omitempty"`
}

func (r DEKUnwrapAndEncryptBoundTrackedRequest) Validate() error {
	if err := (DEKUnwrapAndEncryptBoundRequest{EncryptedDEKB64: r.EncryptedDEKB64, TokenExpiry: r.TokenExpiry, PlaintextB64: r.PlaintextB64}).Validate(); err != nil {
		return err
	}
	if err := requireMessageUUID(r.EntryID, "entry_id"); err != nil {
		return err
	}
	if r.PreviousRecord != nil {
		return r.PreviousRecord.validate()
	}
	return nil
}

// DEKUnwrapAndEncryptBoundTrackedResponseData — the personal bound token plus
// the change verdict and the record that replaces the previous one.
type DEKUnwrapAndEncryptBoundTrackedResponseData struct {
	IVB64         string       `json:"iv_b64"`
	CiphertextB64 string       `json:"ciphertext_b64"`
	ChangeVerdict string       `json:"change_verdict"`
	ChangeRecord  ChangeRecord `json:"change_record"`
}
