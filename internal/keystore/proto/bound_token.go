// bound_token.go — bound drag tokens: authenticated expiry and ownership scope.
//
// A drag token made before this format carried its `E=` expiry outside the
// GCM tag, so anyone able to rewrite the header could change or drop it. The
// Keeper cannot tell such a body from a bound one by its bytes, so it refuses
// the AAD-free drag actions outright (TokenLegacyRefused) and opens drag
// tokens only through the bound actions below.
//
// A bound token is sealed with an AAD the Keeper builds from validated
// fields; no caller supplies it:
//
//	dragpass.drag.token|1|personal|<account_id>|-|<dek_version>|-|<expiry>
//	dragpass.drag.token|1|group|<org_id>|<group_id>|<dek_version>|<table_id or ->|<expiry>
//
// <expiry> is a canonical decimal Unix-seconds value or the word `never`, the
// explicit no-expiry state. Changing, dropping or moving any field fails the
// tag. The personal account id is the Keeper's own signed-in account binding,
// never a caller value, and never appears in the token.
//
// This is a viewing control for clients that run these checks. It does not
// recall plaintext or keys a reader already obtained.
//
// Contract: docs/protocol.md "Bound drag tokens".

package proto

import (
	"strconv"
	"strings"
)

// BoundTokenAADDomain starts with "dragpass.drag.", which ReservedAADDomains
// refuses for any caller-chosen AAD.
const (
	BoundTokenAADDomain     = "dragpass.drag.token"
	boundTokenSchemaVersion = "1"
	boundTokenNever         = "never"
	boundTokenNone          = "-"
	// boundTokenPersonalDekVersion — the personal DEK does not rotate.
	boundTokenPersonalDekVersion = 1
	boundTokenMaxExpiryDigits    = 11
)

// Error codes carried in the envelope's error_code.
const (
	// TokenLegacyRefused — an AAD-free drag action, or an audit request
	// without token_expiry. Its expiry cannot be authenticated.
	TokenLegacyRefused = "TOKEN_LEGACY_REFUSED"
	// TokenExpired — the bound token's authenticated expiry has passed.
	TokenExpired = "TOKEN_EXPIRED"
	// TokenInvalidInput — a malformed bound request field.
	TokenInvalidInput = "TOKEN_INVALID_INPUT"
	// TokenScopeMismatch — the handle was opened for another org, group or
	// version than the request names, or from an audit-only grant.
	TokenScopeMismatch = "TOKEN_SCOPE_MISMATCH"
	// TokenAccountUnbound — a personal bound action on a device with no
	// signed-in account binding.
	TokenAccountUnbound = "TOKEN_ACCOUNT_UNBOUND"
	// TokenDecryptFailed — the GCM tag did not verify under the bound AAD.
	TokenDecryptFailed = "TOKEN_DECRYPT_FAILED"
)

// TokenExpiry is an authenticated expiry. The zero value is the explicit
// no-expiry state; it is only ever produced by ParseTokenExpiry("never").
type TokenExpiry struct {
	ExpiresAt int64 // Unix seconds; 0 means never
}

// Never reports the explicit no-expiry state.
func (e TokenExpiry) Never() bool { return e.ExpiresAt == 0 }

// ExpiredAt reports whether the token may no longer be opened at now (Unix
// seconds). A token is viewable strictly before ExpiresAt, with no grace.
func (e TokenExpiry) ExpiredAt(now int64) bool {
	return !e.Never() && now >= e.ExpiresAt
}

func (e TokenExpiry) canonical() string {
	if e.Never() {
		return boundTokenNever
	}
	return strconv.FormatInt(e.ExpiresAt, 10)
}

// ParseTokenExpiry reads the token_expiry request field: `never`, or a
// canonical positive decimal of at most 11 digits. An empty value is not
// "no expiry".
func ParseTokenExpiry(value string) (TokenExpiry, error) {
	if value == boundTokenNever {
		return TokenExpiry{}, nil
	}
	if value == "" || len(value) > boundTokenMaxExpiryDigits || value[0] == '0' {
		return TokenExpiry{}, newValidationError("token_expiry", "must be never or a canonical positive Unix-seconds value")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return TokenExpiry{}, newValidationError("token_expiry", "must be never or a canonical positive Unix-seconds value")
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 {
		return TokenExpiry{}, newValidationError("token_expiry", "must be never or a canonical positive Unix-seconds value")
	}
	return TokenExpiry{ExpiresAt: n}, nil
}

// BoundPersonalTokenAAD is the AAD of a personal bound token.
func BoundPersonalTokenAAD(accountID string, expiry TokenExpiry) string {
	return strings.Join([]string{
		BoundTokenAADDomain, boundTokenSchemaVersion, "personal",
		accountID, boundTokenNone, strconv.Itoa(boundTokenPersonalDekVersion), boundTokenNone,
		expiry.canonical(),
	}, "|")
}

// BoundGroupTokenAAD is the AAD of a Group bound token. auditTableID is empty
// for a token without A=.
func BoundGroupTokenAAD(orgID, groupID string, dekVersion int, auditTableID string, expiry TokenExpiry) string {
	table := auditTableID
	if table == "" {
		table = boundTokenNone
	}
	return strings.Join([]string{
		BoundTokenAADDomain, boundTokenSchemaVersion, "group",
		orgID, groupID, strconv.Itoa(dekVersion), table,
		expiry.canonical(),
	}, "|")
}

// DEKUnwrapAndEncryptBoundRequest seals a personal bound token.
type DEKUnwrapAndEncryptBoundRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64,omitempty"` // empty: the Keeper's own slot
	TokenExpiry     string `json:"token_expiry"`
	PlaintextB64    string `json:"plaintext_b64"` // secret in REQUEST only; never logged
}

func (r DEKUnwrapAndEncryptBoundRequest) Validate() error {
	if err := optionalDeviceWrappedDEK(r.EncryptedDEKB64); err != nil {
		return err
	}
	if _, err := ParseTokenExpiry(r.TokenExpiry); err != nil {
		return err
	}
	_, err := requireBase64(r.PlaintextB64, "plaintext_b64")
	return err
}

// DEKUnwrapAndDecryptBoundToClipboardRequest opens a personal bound token
// into the OS clipboard.
type DEKUnwrapAndDecryptBoundToClipboardRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64,omitempty"`
	TokenExpiry     string `json:"token_expiry"`
	IVB64           string `json:"iv_b64"`
	CiphertextB64   string `json:"ciphertext_b64"`
	ClipboardTTLMs  int64  `json:"clipboard_ttl_ms"`
}

func (r DEKUnwrapAndDecryptBoundToClipboardRequest) Validate() error {
	if err := optionalDeviceWrappedDEK(r.EncryptedDEKB64); err != nil {
		return err
	}
	if _, err := ParseTokenExpiry(r.TokenExpiry); err != nil {
		return err
	}
	if err := validateAuditSealed(r.IVB64, r.CiphertextB64); err != nil {
		return err
	}
	return validateClipboardTTL(r.ClipboardTTLMs)
}

// GroupBoundTokenContext is the scope a Group bound token is sealed under.
type GroupBoundTokenContext struct {
	GroupHandle  string
	OrgID        string
	GroupID      string
	DekVersion   int
	AuditTableID string // empty: no A= slot
	TokenExpiry  string
}

func (c GroupBoundTokenContext) validate() error {
	if err := requireHandle(c.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if err := requireMessageUUID(c.OrgID, "org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(c.GroupID, "group_id"); err != nil {
		return err
	}
	if err := requireMessageDekVersion(c.DekVersion, "dek_version"); err != nil {
		return err
	}
	if c.AuditTableID != "" {
		if err := requireMessageUUID(c.AuditTableID, "audit_table_id"); err != nil {
			return err
		}
	}
	_, err := ParseTokenExpiry(c.TokenExpiry)
	return err
}

// GroupEncryptBoundRequest seals a Group bound token. The fields are flat so
// the no-raw-secret guards see every field that crosses.
type GroupEncryptBoundRequest struct {
	GroupHandle  string `json:"group_handle"`
	OrgID        string `json:"org_id"`
	GroupID      string `json:"group_id"`
	DekVersion   int    `json:"dek_version"`
	AuditTableID string `json:"audit_table_id,omitempty"`
	TokenExpiry  string `json:"token_expiry"`
	PlaintextB64 string `json:"plaintext_b64"` // secret in REQUEST only; never logged
}

func (r GroupEncryptBoundRequest) TokenContext() GroupBoundTokenContext {
	return GroupBoundTokenContext{r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.AuditTableID, r.TokenExpiry}
}

func (r GroupEncryptBoundRequest) Validate() error {
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	_, err := requireBase64(r.PlaintextB64, "plaintext_b64")
	return err
}

// GroupDecryptBoundToClipboardRequest opens a Group bound token into the OS
// clipboard.
type GroupDecryptBoundToClipboardRequest struct {
	GroupHandle    string `json:"group_handle"`
	OrgID          string `json:"org_id"`
	GroupID        string `json:"group_id"`
	DekVersion     int    `json:"dek_version"`
	AuditTableID   string `json:"audit_table_id,omitempty"`
	TokenExpiry    string `json:"token_expiry"`
	IVB64          string `json:"iv_b64"`
	CiphertextB64  string `json:"ciphertext_b64"`
	ClipboardTTLMs int64  `json:"clipboard_ttl_ms"`
}

func (r GroupDecryptBoundToClipboardRequest) TokenContext() GroupBoundTokenContext {
	return GroupBoundTokenContext{r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.AuditTableID, r.TokenExpiry}
}

func (r GroupDecryptBoundToClipboardRequest) Validate() error {
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	if err := validateAuditSealed(r.IVB64, r.CiphertextB64); err != nil {
		return err
	}
	return validateClipboardTTL(r.ClipboardTTLMs)
}
