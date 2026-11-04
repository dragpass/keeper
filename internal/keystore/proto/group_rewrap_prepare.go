package proto

// GroupRewrapPrepareRequest asks Keeper to bind one stored member grant and
// named recipient before the App requests an online server decision.
type GroupRewrapPrepareRequest struct {
	Operation            string                    `json:"operation"`
	SourceKind           string                    `json:"source_kind"`
	TokenID              string                    `json:"token_id"`
	SessionIssuedAtNanos int64                     `json:"session_issued_at_nanos,string"`
	Member               DEKRewrapForMemberRequest `json:"member"`
}

func (r GroupRewrapPrepareRequest) Validate() error {
	if r.Operation != "member_invite" && r.Operation != "member_add" {
		return newValidationError("operation", "unsupported rewrap operation")
	}
	if r.SourceKind != "stored_member" {
		return newValidationError("source_kind", "unsupported rewrap source")
	}
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	if r.SessionIssuedAtNanos <= 0 {
		return newValidationError("session_issued_at_nanos", "must be positive")
	}
	if err := r.Member.Validate(); err != nil {
		return err
	}
	if r.Member.OwnerAccountID == "" || r.Member.OtherAccountID == "" || r.Member.GrantContext == nil {
		return newValidationError("member", "named source and recipient with grant context required")
	}
	return nil
}

type GroupRewrapPrepareResponseData struct {
	Challenge               string `json:"challenge"`
	Operation               string `json:"operation"`
	OrgID                   string `json:"org_id"`
	GroupID                 string `json:"group_id"`
	DEKVersion              int    `json:"dek_version"`
	SourceKind              string `json:"source_kind"`
	SourceGrantDigest       string `json:"source_grant_digest"`
	SourcePolicy            string `json:"source_policy"`
	OutputPolicy            string `json:"output_policy"`
	RequestDigest           string `json:"request_digest"`
	RecipientsDigest        string `json:"recipients_digest"`
	RecipientAccountID      string `json:"recipient_account_id"`
	RecipientKeyFingerprint string `json:"recipient_key_fingerprint"`
}
