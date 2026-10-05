// device_identity.go — device id, account binding and device sign-out
// payloads (0.0.58). Nothing here is key material.

package proto

// AccountAliasMaxBytes is ariadne's alias column width. The Keeper checks
// the shape loosely (it is a hint, never an identity) but keeps anything it
// could not be out of the keychain.
const AccountAliasMaxBytes = 32

// DeviceIDEnsureRequest optionally names the id the caller already uses. It
// is adopted only when no id is stored and no MLS leaf record names one.
type DeviceIDEnsureRequest struct {
	CandidateDeviceID string `json:"candidate_device_id,omitempty"`
}

func (r *DeviceIDEnsureRequest) Validate() error {
	return requireOptionalAccountUUID(r.CandidateDeviceID, "candidate_device_id")
}

// DeviceIDEnsureResponseData is the id and where it came from:
// stored | leaf | candidate | generated.
type DeviceIDEnsureResponseData struct {
	DeviceID string `json:"device_id"`
	Source   string `json:"source"`
}

// AccountBindingSetRequest is the account the App just signed in to.
type AccountBindingSetRequest struct {
	AccountID string `json:"account_id"`
	Alias     string `json:"alias"`
}

func (r *AccountBindingSetRequest) Validate() error {
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	return requireAccountAlias(r.Alias, "alias")
}

// AccountBindingSetResponseData says whether the record changed and what it
// now holds.
type AccountBindingSetResponseData struct {
	Changed    bool   `json:"changed"`
	Generation uint64 `json:"generation"`
}

// DeviceAccountStatusRequest takes no input.
type DeviceAccountStatusRequest struct{}

// DeviceAccountStatusResponseData is what the Extension needs to decide
// whether to sign itself in. The fingerprint is of the public account key.
type DeviceAccountStatusResponseData struct {
	DeviceID              string `json:"device_id,omitempty"`
	AccountID             string `json:"account_id,omitempty"`
	Alias                 string `json:"alias,omitempty"`
	Generation            uint64 `json:"generation"`
	AccountKeyFingerprint string `json:"account_key_fingerprint,omitempty"`
	DeviceMasterPresent   bool   `json:"device_master_present"`
	SignedOut             bool   `json:"signed_out"`
}

// DeviceSignoutRequest takes no input.
type DeviceSignoutRequest struct{}

// DeviceSignoutResponseData reports what the sign-out removed.
type DeviceSignoutResponseData struct {
	DeviceMasterRemoved bool   `json:"device_master_removed"`
	ClosedGroupSessions int    `json:"closed_group_sessions"`
	Generation          uint64 `json:"generation"`
}

// requireAccountAlias accepts what ariadne's accountalias validator could
// accept: 3..32 bytes of lowercase ASCII letters, digits and . _ -, starting
// with a letter. The server stays the judge of the exact grammar.
func requireAccountAlias(value, field string) error {
	if len(value) < 3 || len(value) > AccountAliasMaxBytes {
		return newValidationError(field, "must be 3..32 characters")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		letter := c >= 'a' && c <= 'z'
		if i == 0 && !letter {
			return newValidationError(field, "must start with a lowercase letter")
		}
		if !letter && !(c >= '0' && c <= '9') && c != '.' && c != '_' && c != '-' {
			return newValidationError(field, "must be lowercase letters, digits, '.', '_' or '-'")
		}
	}
	return nil
}
