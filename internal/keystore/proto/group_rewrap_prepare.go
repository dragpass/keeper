package proto

// GroupRewrapPrepareRequest binds one member or ordered batch rewrap before
// the App requests an online server decision.
type GroupRewrapPrepareRequest struct {
	Archive              *ArchiveUnwrapAndRewrapRequest        `json:"archive,omitempty"`
	Combine              *ArchiveQuorumCombineAndRewrapRequest `json:"combine,omitempty"`
	Operation            string                                `json:"operation"`
	SourceKind           string                                `json:"source_kind"`
	TokenID              string                                `json:"token_id"`
	SessionIssuedAtNanos int64                                 `json:"session_issued_at_nanos,string"`
	Member               DEKRewrapForMemberRequest             `json:"member"`
	Many                 *DEKUnwrapAndRewrapForManyRequest     `json:"many,omitempty"`
}

func (r GroupRewrapPrepareRequest) Validate() error {
	if r.Archive != nil {
		member := r.Operation == "archive_member_regrant" && r.Archive.RecipientAccountID != "" && r.Archive.ArchiveRecipientAccountID == ""
		handoff := r.Operation == "archive_handoff" && r.Archive.ArchiveRecipientAccountID != "" && r.Archive.RecipientAccountID == ""
		if r.Many != nil || r.Combine != nil || r.Member.WrappedForMeB64 != "" || (!member && !handoff) || r.SourceKind != "stored_archive" || r.Archive.Decision != nil || r.Archive.GrantContext == nil || r.Archive.OwnerAccountID == "" {
			return newValidationError("archive", "exact archive operation context required")
		}
		if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
			return err
		}
		if r.SessionIssuedAtNanos <= 0 {
			return newValidationError("session_issued_at_nanos", "must be positive")
		}
		return r.Archive.Validate()
	}
	if r.Combine != nil {
		if r.Many != nil || r.Member.WrappedForMeB64 != "" || r.Operation != "quorum_combine" || r.SourceKind != "archive_quorum" || r.Combine.Decision != nil || r.Combine.GrantContext == nil || r.Combine.OwnerAccountID == "" {
			return newValidationError("combine", "exact combine context required")
		}
		if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
			return err
		}
		if err := requireMessageUUID(r.Combine.RecoverySessionID, "recovery_session_id"); err != nil {
			return err
		}
		if r.SessionIssuedAtNanos <= 0 {
			return newValidationError("session_issued_at_nanos", "must be positive")
		}
		return r.Combine.Validate()
	}
	if r.Many != nil {
		if (r.Operation != "rotation_old_grants" || r.SourceKind != "stored_member") &&
			(r.Operation != "audit_relabel" || r.SourceKind != "retained_member") &&
			(r.Operation != "rotation_new_dek" || r.SourceKind != "keeper_generated") {
			return newValidationError("operation", "unsupported batch rewrap context")
		}
		if (r.SourceKind == "keeper_generated") != (r.Many.SourceHandle != "") {
			return newValidationError("many.source_handle", "generated source requires its handle")
		}
		if r.Member.WrappedForMeB64 != "" || r.Many.Decision != nil ||
			r.Many.OwnerAccountID == "" || r.Many.GrantContext == nil {
			return newValidationError("many", "named source, grant context and no prior decision required")
		}
		if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
			return err
		}
		if r.SessionIssuedAtNanos <= 0 {
			return newValidationError("session_issued_at_nanos", "must be positive")
		}
		return r.Many.Validate()
	}
	if !ValidMemberRewrapContext(r.Operation, r.SourceKind) {
		return newValidationError("operation", "unsupported member rewrap context")
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
	Challenge               string                      `json:"challenge"`
	Operation               string                      `json:"operation"`
	OrgID                   string                      `json:"org_id"`
	GroupID                 string                      `json:"group_id"`
	DEKVersion              int                         `json:"dek_version"`
	SourceKind              string                      `json:"source_kind"`
	SourceGrantDigest       string                      `json:"source_grant_digest"`
	SourcePolicy            string                      `json:"source_policy"`
	OutputPolicy            string                      `json:"output_policy"`
	RequestDigest           string                      `json:"request_digest"`
	RecipientsDigest        string                      `json:"recipients_digest"`
	Recipients              []RewrapRecipientCommitment `json:"recipients,omitempty"`
	RecipientAccountID      string                      `json:"recipient_account_id"`
	RecipientKeyFingerprint string                      `json:"recipient_key_fingerprint"`
}

// ValidMemberRewrapContext keeps preparation and execution on the same
// operation/source allowlist. A server decision must still authorize it.
func ValidMemberRewrapContext(operation, source string) bool {
	return ((operation == "member_invite" || operation == "member_add" || operation == "member_key_refresh_current") && source == "stored_member") ||
		((operation == "member_backfill" || operation == "member_key_refresh_retained") && source == "retained_member")
}
