package proto

import (
	"strconv"
	"strings"
)

// GroupRewrapDecision is a signed statement for one exact Keeper challenge.
// Its fields are not authority until Keeper verifies the signature and state.
type GroupRewrapDecision struct {
	Challenge            string `json:"challenge"`
	AccountID            string `json:"account_id"`
	DeviceID             string `json:"device_id"`
	TokenID              string `json:"token_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos,string"`
	Operation            string `json:"operation"`
	OrgID                string `json:"org_id"`
	GroupID              string `json:"group_id"`
	DEKVersion           int    `json:"dek_version"`
	SourceKind           string `json:"source_kind"`
	SourceGrantDigest    string `json:"source_grant_digest"`
	SourcePolicy         string `json:"source_policy"`
	OutputPolicy         string `json:"output_policy"`
	RequestDigest        string `json:"request_digest"`
	RecipientsDigest     string `json:"recipients_digest"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ServerKeyVersion     uint   `json:"server_key_version"`
	Signature            string `json:"signature"`
}

// GroupRewrapDecisionCanonical must match Ariadne's signing bytes exactly.
// The caller validates every field before signing or accepting the decision.
func GroupRewrapDecisionCanonical(d GroupRewrapDecision) string {
	fields := []string{d.Challenge, d.AccountID, d.DeviceID,
		d.TokenID, strconv.FormatInt(d.SessionIssuedAtNanos, 10), d.Operation,
		d.OrgID, d.GroupID, strconv.Itoa(d.DEKVersion), d.SourceKind,
		d.SourceGrantDigest, d.SourcePolicy, d.OutputPolicy, d.RequestDigest,
		d.RecipientsDigest, strconv.FormatInt(d.IssuedAt, 10),
		strconv.FormatInt(d.ExpiresAt, 10), strconv.FormatUint(uint64(d.ServerKeyVersion), 10),
	}
	var canonical strings.Builder
	canonical.WriteString("dragpass.group.rewrap|1")
	for _, field := range fields {
		canonical.WriteByte('|')
		canonical.WriteString(strconv.Itoa(len(field)))
		canonical.WriteByte(':')
		canonical.WriteString(field)
	}
	return canonical.String()
}
