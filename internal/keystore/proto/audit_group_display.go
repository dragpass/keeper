package proto

import (
	"crypto/sha256"
	"strconv"
	"strings"
)

const AuditGroupDisplayMaxRequestBytes = 20 * 1024

type AuditGroupDisplayDecision struct {
	CurrentGroupDisplayDecision
	TableID     string `json:"table_id"`
	TableDigest string `json:"table_digest"`
}

func (d AuditGroupDisplayDecision) Validate() error {
	if err := d.CurrentGroupDisplayDecision.Validate(); err != nil {
		return err
	}
	if err := requireMessageUUID(d.TableID, "decision.table_id"); err != nil {
		return err
	}
	if err := requireMessageDigest(d.TableDigest, "decision.table_digest"); err != nil {
		return err
	}
	if d.TableDigest == strings.Repeat("0", 64) {
		return newValidationError("decision.table_digest", "must not be zero")
	}
	return nil
}

// AuditGroupDisplayDecisionCanonical matches Ariadne's separate audit domain.
func AuditGroupDisplayDecisionCanonical(d AuditGroupDisplayDecision) string {
	return strings.Join([]string{
		"dragpass.group.audit-display", "1", d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.GroupID,
		strconv.Itoa(d.DekVersion), d.GrantDigest, d.TableID, d.TableDigest,
		d.OperationDigest, d.FrameKeyDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}, "|")
}

type AuditGroupDisplayPrepareRequest struct {
	GroupHandle           string             `json:"group_handle"`
	Token                 string             `json:"token"`
	IVB64                 string             `json:"iv_b64"`
	CiphertextB64         string             `json:"ciphertext_b64"`
	FramePublicKeySPKIB64 string             `json:"frame_public_key_spki_b64"`
	TokenID               string             `json:"token_id"`
	SessionIssuedAtNanos  string             `json:"session_issued_at_nanos"`
	OrgID                 string             `json:"org_id"`
	GroupID               string             `json:"group_id"`
	DekVersion            int                `json:"dek_version"`
	TableID               string             `json:"table_id"`
	TableB64              string             `json:"table_b64"`
	Permit                AuditDecryptPermit `json:"permit"`
	TokenExpiry           string             `json:"token_expiry,omitempty"`
}

func (r AuditGroupDisplayPrepareRequest) Validate() error {
	base := CurrentGroupDisplayPrepareRequest{
		GroupHandle: r.GroupHandle, Token: r.Token, IVB64: r.IVB64,
		CiphertextB64: r.CiphertextB64, FramePublicKeySPKIB64: r.FramePublicKeySPKIB64,
		TokenID: r.TokenID, SessionIssuedAtNanos: r.SessionIssuedAtNanos,
		OrgID: r.OrgID, GroupID: r.GroupID, DekVersion: r.DekVersion, TokenExpiry: r.TokenExpiry,
	}
	if err := base.Validate(); err != nil {
		return err
	}
	if err := r.TokenContext().validate(); err != nil {
		return err
	}
	return r.Permit.Validate()
}

func (r AuditGroupDisplayPrepareRequest) TokenContext() AuditTokenContext {
	return AuditTokenContext{
		GroupHandle: r.GroupHandle, OrgID: r.OrgID, GroupID: r.GroupID,
		DekVersion: r.DekVersion, TableID: r.TableID, TableB64: r.TableB64,
		TokenExpiry: r.TokenExpiry,
	}
}

type AuditGroupDisplayPrepareResponseData struct {
	Challenge       string `json:"challenge"`
	GroupID         string `json:"group_id"`
	DekVersion      int    `json:"dek_version"`
	GrantDigest     string `json:"grant_digest"`
	TableID         string `json:"table_id"`
	TableDigest     string `json:"table_digest"`
	OperationDigest string `json:"operation_digest"`
	FrameKeyDigest  string `json:"frame_key_digest"`
}

type AuditGroupDisplayExecuteRequest struct {
	Prepare  AuditGroupDisplayPrepareRequest `json:"prepare"`
	Decision AuditGroupDisplayDecision       `json:"decision"`
}

func (r AuditGroupDisplayExecuteRequest) Validate() error {
	if err := r.Prepare.Validate(); err != nil {
		return err
	}
	return r.Decision.Validate()
}

type AuditGroupDisplayOperation struct {
	CurrentGroupDisplayOperation
	OrgID      string
	GroupID    string
	DekVersion int
	TableID    string
	Table      []byte
	Permit     AuditDecryptPermit
}

// AuditGroupDisplayOperationDigest commits to the exact audit token, permit,
// table bytes, Keeper handle and receiving frame without sending them to API.
func AuditGroupDisplayOperationDigest(op AuditGroupDisplayOperation) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("dragpass.group.audit-display.operation\x00\x01"))
	writeGroupDisplayDigestField(h, op.Challenge[:])
	writeGroupDisplayDigestField(h, op.GroupHandle[:])
	writeGroupDisplayDigestField(h, op.Token)
	writeGroupDisplayDigestField(h, op.IV[:])
	writeGroupDisplayDigestField(h, op.Ciphertext)
	writeGroupDisplayDigestField(h, op.FramePublicKeySPKI)
	writeGroupDisplayDigestField(h, []byte(op.OrgID))
	writeGroupDisplayDigestField(h, []byte(op.GroupID))
	writeGroupDisplayDigestField(h, []byte(strconv.Itoa(op.DekVersion)))
	writeGroupDisplayDigestField(h, []byte(op.TableID))
	writeGroupDisplayDigestField(h, op.Table)
	writeGroupDisplayDigestField(h, []byte(AuditDecryptPermitCanonical(op.Permit)))
	writeGroupDisplayDigestField(h, []byte(op.Permit.Signature))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
