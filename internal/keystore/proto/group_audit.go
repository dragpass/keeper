// group_audit.go — audit-only Group DEK versions: the grant policy context,
// the drag audit AAD, the per-token key derivation input, and the two
// server-signed authorizations (table receipt, decrypt permit).
//
// An org that turns audit mode on rotates its default Access Group DEK to a
// version whose grants are RSA-OAEP wrapped under a label that names the
// policy. A handle opened from such a grant remembers the policy, refuses the
// AAD-free drag actions, and serves only the three audit actions, each of
// which requires a server signature and consumes it once in this process.
//
// None of this reaches back: tokens made before the rotation, and devices
// that already hold the earlier version's grant, keep opening those tokens.
//
// Contract: dragpass-control-plane docs/security/threat-model.md §4.13 and
// docs/protocol.md "Audit-only Group DEK versions".

package proto

import (
	"math"
	"strconv"
	"strings"
)

// Grant policies. A version with no policy on record is legacy.
const (
	GrantPolicyLegacy      = "legacy"
	GrantPolicyAuditOnlyV1 = "audit_only_v1"
	// GrantPolicyDecryptOnlyV1 — a legacy version an audit switch retired. Its
	// grants are rewrapped under a label naming this policy, and a handle
	// opened from one opens existing tokens but seals nothing under the DEK.
	GrantPolicyDecryptOnlyV1 = "decrypt_only_v1"
)

// Canonical domains. Each is the first slot of a pipe-joined canonical whose
// other slots are UUIDs, lowercase hex and decimal integers, so no slot can
// carry a '|'.
const (
	GroupDEKGrantLabelDomain = "dragpass.group-dek"
	AuditDragAADDomain       = "dragpass.drag.audit"
	AuditTableReceiptDomain  = "dragpass.audit.table-receipt"
	AuditDecryptPermitDomain = "dragpass.audit.decrypt-permit"
	auditCanonicalVersion    = "1"
)

const (
	// AuditTableReceiptTTLSeconds / AuditDecryptPermitTTLSeconds — the server
	// signs exactly these spans and the Keeper requires them.
	AuditTableReceiptTTLSeconds  = 60
	AuditDecryptPermitTTLSeconds = 30

	// AuditShuffleTableBytes — the server's audit shuffle table is a 256-byte
	// permutation; it is also the HKDF salt input of an audit token key.
	AuditShuffleTableBytes = 256

	// AuditMaxRequestBytes caps the audit actions before they are decoded.
	AuditMaxRequestBytes = 1024 * 1024
)

// ReservedAADDomains — AAD domains whose open the Keeper builds itself, behind
// its own checks: the audit drag token and the Secure Message. A caller-chosen
// AAD (group_encrypt_with_aad, the credential sinks) may not start with one,
// so no caller can seal or open under a domain whose checks it skipped.
// dragpass.room is not here: the Keeper's own room-row-name route seals it
// through group_encrypt_with_aad under a throwaway key nobody opens.
var ReservedAADDomains = []string{
	"dragpass.drag.", // AuditDragAADDomain and any later drag domain
	MessageAADDomain,
}

// Error codes carried in the envelope's error_code.
const (
	// GroupPolicyAuditOnly — an AAD-free drag action on a handle opened from an
	// audit-only grant.
	GroupPolicyAuditOnly = "GROUP_POLICY_AUDIT_ONLY"
	// GroupPolicyNotAuditOnly — an audit action on a handle that was not opened
	// from an audit-only grant, or whose org / group / version differ.
	GroupPolicyNotAuditOnly = "GROUP_POLICY_NOT_AUDIT_ONLY"
	// GroupPolicyDecryptOnly — a seal (group_encrypt, group_encrypt_with_aad,
	// message_seal) on a handle opened from a decrypt-only grant.
	GroupPolicyDecryptOnly = "GROUP_POLICY_DECRYPT_ONLY"
	// GroupGrantPolicyMismatch — a grant did not open under the audit-only
	// label it was presented with. Either the grant was wrapped without the
	// label (a broken or tampered rotation) or it is not this account's grant.
	GroupGrantPolicyMismatch = "GROUP_GRANT_POLICY_MISMATCH"
	// AuditInvalidInput — malformed, unknown, duplicate or missing field.
	AuditInvalidInput = "AUDIT_INVALID_INPUT"
	// AuditNotAuthorized — receipt / permit binding, window, signature, or
	// single-use failure. One code for all of them.
	AuditNotAuthorized = "AUDIT_NOT_AUTHORIZED"
	// AuditAccountMismatch — the receipt / permit names another account than
	// the one this device's account binding records.
	AuditAccountMismatch = "AUDIT_ACCOUNT_MISMATCH"
	// AuditAccountUnbound — this device has no account binding, or it is
	// signed out, so no receipt / permit can be matched to an account.
	AuditAccountUnbound = "AUDIT_ACCOUNT_UNBOUND"
	// AuditBusy — the process-local single-use record is full.
	AuditBusy = "AUDIT_BUSY"
	// AuditDecryptFailed — GCM tag failure under the derived token key.
	AuditDecryptFailed = "AUDIT_DECRYPT_FAILED"
)

// GrantContext names the Group DEK version a grant belongs to and the policy
// it was wrapped under. The server states it; the Keeper builds the OAEP label
// from it. Absent means legacy, the empty label every grant used before.
//
// Lying about it gains nothing: an audit-only grant does not open under the
// empty label, and a legacy grant does not open under the audit-only label.
type GrantContext struct {
	Policy     string `json:"policy"`
	OrgID      string `json:"org_id"`
	GroupID    string `json:"group_id"`
	DekVersion int    `json:"dek_version"`
}

// IsAuditOnly reports whether c names the audit-only policy. Nil is legacy.
func (c *GrantContext) IsAuditOnly() bool {
	return c != nil && c.Policy == GrantPolicyAuditOnlyV1
}

// IsDecryptOnly reports whether c names the decrypt-only policy.
func (c *GrantContext) IsDecryptOnly() bool {
	return c != nil && c.Policy == GrantPolicyDecryptOnlyV1
}

// IsLabeled reports whether a grant under c carries an OAEP label: every
// policy but legacy does.
func (c *GrantContext) IsLabeled() bool {
	return c.IsAuditOnly() || c.IsDecryptOnly()
}

func validateGrantContext(c *GrantContext, field string) error {
	if c == nil {
		return nil
	}
	if c.Policy != GrantPolicyLegacy && c.Policy != GrantPolicyAuditOnlyV1 && c.Policy != GrantPolicyDecryptOnlyV1 {
		return newValidationError(field+".policy", "must be legacy, audit_only_v1 or decrypt_only_v1")
	}
	if err := requireMessageUUID(c.OrgID, field+".org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(c.GroupID, field+".group_id"); err != nil {
		return err
	}
	return requireMessageDekVersion(c.DekVersion, field+".dek_version")
}

// GroupDEKGrantLabel is the RSA-OAEP label of a grant: nil for legacy, the
// policy canonical for audit-only and decrypt-only.
//
//	dragpass.group-dek|1|policy=<audit_only_v1|decrypt_only_v1>|org=<org>|group=<group>|v=<n>
func GroupDEKGrantLabel(c *GrantContext) []byte {
	if !c.IsLabeled() {
		return nil
	}
	return []byte(strings.Join([]string{
		GroupDEKGrantLabelDomain,
		auditCanonicalVersion,
		"policy=" + c.Policy,
		"org=" + c.OrgID,
		"group=" + c.GroupID,
		"v=" + strconv.Itoa(c.DekVersion),
	}, "|"))
}

// AuditDragAADCanonical is the AAD of a drag token sealed under an audit-only
// version. The Keeper builds it from validated fields; no caller supplies it.
//
//	dragpass.drag.audit|1|<org>|<group>|<dek_version>|<table_id>
func AuditDragAADCanonical(orgID, groupID string, dekVersion int, tableID string) string {
	return strings.Join([]string{
		AuditDragAADDomain,
		auditCanonicalVersion,
		orgID,
		groupID,
		strconv.Itoa(dekVersion),
		tableID,
	}, "|")
}

// AuditTableReceipt is the server's statement that it issued this shuffle
// table to this account for this org, group and version, recorded the
// encryption, and allows one token to be sealed with it.
type AuditTableReceipt struct {
	TableID          string `json:"table_id"`
	AccountID        string `json:"account_id"`
	OrgID            string `json:"org_id"`
	GroupID          string `json:"group_id"`
	DekVersion       int    `json:"dek_version"`
	TableSHA256      string `json:"table_sha256"` // lowercase hex SHA-256 of the 256-byte table
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"`
	ServerKeyVersion uint   `json:"server_key_version"`
	Signature        string `json:"signature"` // Base64 RSA-PSS SHA-256 over the canonical
}

// AuditTableReceiptCanonical — the 11-slot string the server signs.
func AuditTableReceiptCanonical(r AuditTableReceipt) string {
	return strings.Join([]string{
		AuditTableReceiptDomain,
		auditCanonicalVersion,
		r.TableID,
		r.AccountID,
		r.OrgID,
		r.GroupID,
		strconv.Itoa(r.DekVersion),
		r.TableSHA256,
		strconv.FormatInt(r.IssuedAt, 10),
		strconv.FormatInt(r.ExpiresAt, 10),
		strconv.FormatUint(uint64(r.ServerKeyVersion), 10),
	}, "|")
}

func (r AuditTableReceipt) Validate() error {
	return validateAuditAuthorization(
		"receipt", nil, r.TableID, r.AccountID, r.OrgID, r.GroupID, r.DekVersion,
		r.TableSHA256, r.IssuedAt, r.ExpiresAt, r.ServerKeyVersion, r.Signature,
	)
}

// AuditDecryptPermit is the server's statement that it disclosed this table to
// this account and recorded the decryption. PermitID makes each disclosure a
// separate single-use authorization.
type AuditDecryptPermit struct {
	PermitID         string `json:"permit_id"`
	TableID          string `json:"table_id"`
	AccountID        string `json:"account_id"`
	OrgID            string `json:"org_id"`
	GroupID          string `json:"group_id"`
	DekVersion       int    `json:"dek_version"`
	TableSHA256      string `json:"table_sha256"`
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"`
	ServerKeyVersion uint   `json:"server_key_version"`
	Signature        string `json:"signature"`
}

// AuditDecryptPermitCanonical — the 12-slot string the server signs.
func AuditDecryptPermitCanonical(p AuditDecryptPermit) string {
	return strings.Join([]string{
		AuditDecryptPermitDomain,
		auditCanonicalVersion,
		p.PermitID,
		p.TableID,
		p.AccountID,
		p.OrgID,
		p.GroupID,
		strconv.Itoa(p.DekVersion),
		p.TableSHA256,
		strconv.FormatInt(p.IssuedAt, 10),
		strconv.FormatInt(p.ExpiresAt, 10),
		strconv.FormatUint(uint64(p.ServerKeyVersion), 10),
	}, "|")
}

func (p AuditDecryptPermit) Validate() error {
	return validateAuditAuthorization(
		"permit", &p.PermitID, p.TableID, p.AccountID, p.OrgID, p.GroupID, p.DekVersion,
		p.TableSHA256, p.IssuedAt, p.ExpiresAt, p.ServerKeyVersion, p.Signature,
	)
}

func validateAuditAuthorization(
	field string, permitID *string,
	tableID, accountID, orgID, groupID string, dekVersion int,
	tableSHA256 string, issuedAt, expiresAt int64, serverKeyVersion uint, signature string,
) error {
	if permitID != nil {
		if err := requireMessageUUID(*permitID, field+".permit_id"); err != nil {
			return err
		}
	}
	for name, id := range map[string]string{
		".table_id": tableID, ".account_id": accountID, ".org_id": orgID, ".group_id": groupID,
	} {
		if err := requireMessageUUID(id, field+name); err != nil {
			return err
		}
	}
	if err := requireMessageDekVersion(dekVersion, field+".dek_version"); err != nil {
		return err
	}
	if err := requireMessageDigest(tableSHA256, field+".table_sha256"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(issuedAt, field+".issued_at"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(expiresAt, field+".expires_at"); err != nil {
		return err
	}
	if serverKeyVersion < 1 || serverKeyVersion > math.MaxUint32 {
		return newValidationError(field+".server_key_version", "must be a positive uint32")
	}
	if _, err := requireBase64(signature, field+".signature"); err != nil {
		return err
	}
	return nil
}

// AuditTokenContext is what every audit action names: the version and table
// the token belongs to, and the table bytes the token key is derived from.
type AuditTokenContext struct {
	GroupHandle string `json:"group_handle"`
	OrgID       string `json:"org_id"`
	GroupID     string `json:"group_id"`
	DekVersion  int    `json:"dek_version"`
	TableID     string `json:"table_id"`
	TableB64    string `json:"table_b64"` // the 256-byte shuffle table, standard Base64
}

func (c AuditTokenContext) validate() error {
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
	if err := requireMessageUUID(c.TableID, "table_id"); err != nil {
		return err
	}
	return requireMessageBase64Len(c.TableB64, "table_b64", AuditShuffleTableBytes, AuditShuffleTableBytes)
}

// GroupEncryptAuditRequest seals one drag token under an audit-only version.
// The field set is flat rather than embedding AuditTokenContext so the strict
// decoder and the no-raw-secret guards see every field that crosses.
type GroupEncryptAuditRequest struct {
	GroupHandle  string            `json:"group_handle"`
	OrgID        string            `json:"org_id"`
	GroupID      string            `json:"group_id"`
	DekVersion   int               `json:"dek_version"`
	TableID      string            `json:"table_id"`
	TableB64     string            `json:"table_b64"`
	Receipt      AuditTableReceipt `json:"receipt"`
	PlaintextB64 string            `json:"plaintext_b64"` // secret in REQUEST only; never logged
}

func (r GroupEncryptAuditRequest) TokenContext() AuditTokenContext {
	return AuditTokenContext{r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.TableID, r.TableB64}
}

func (r GroupEncryptAuditRequest) Validate() error {
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	return r.Receipt.Validate()
}

// GroupDecryptAuditToClipboardRequest opens one audit token into the OS
// clipboard.
type GroupDecryptAuditToClipboardRequest struct {
	GroupHandle    string             `json:"group_handle"`
	OrgID          string             `json:"org_id"`
	GroupID        string             `json:"group_id"`
	DekVersion     int                `json:"dek_version"`
	TableID        string             `json:"table_id"`
	TableB64       string             `json:"table_b64"`
	Permit         AuditDecryptPermit `json:"permit"`
	IVB64          string             `json:"iv_b64"`
	CiphertextB64  string             `json:"ciphertext_b64"`
	ClipboardTTLMs int64              `json:"clipboard_ttl_ms"`
}

func (r GroupDecryptAuditToClipboardRequest) TokenContext() AuditTokenContext {
	return AuditTokenContext{r.GroupHandle, r.OrgID, r.GroupID, r.DekVersion, r.TableID, r.TableB64}
}

func (r GroupDecryptAuditToClipboardRequest) Validate() error {
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	if err := validateAuditSealed(r.IVB64, r.CiphertextB64); err != nil {
		return err
	}
	if err := validateClipboardTTL(r.ClipboardTTLMs); err != nil {
		return err
	}
	return r.Permit.Validate()
}

func validateAuditSealed(ivB64, ciphertextB64 string) error {
	if err := requireMessageBase64Len(ivB64, "iv_b64", 12, 12); err != nil {
		return err
	}
	// ciphertext ‖ 16-byte tag; an empty plaintext is still 16 bytes.
	return requireMessageBase64Len(ciphertextB64, "ciphertext_b64", 16, AuditMaxRequestBytes)
}

// rejectReservedAAD refuses a caller-chosen AAD in a domain the Keeper builds
// itself. It decodes with every alphabet requireBase64 accepts, so no spelling
// of the same bytes slips past.
func rejectReservedAAD(aadB64, field string) error {
	aad, err := requireBase64(aadB64, field)
	if err != nil {
		return err
	}
	for _, domain := range ReservedAADDomains {
		if strings.HasPrefix(string(aad), domain) {
			return newValidationError(field, "must not use a domain the Keeper builds itself")
		}
	}
	return nil
}
