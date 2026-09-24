// mls_roles.go — the wire shapes of room roles and of the signed statements a
// Remove rests on (0.0.55, design Q3 phase 2, Q5 (b), Q13).
//
// The statements are account-key signatures over a canonical, the same shape
// as the rejoin request and the rotation statement: no new crypto. The Keeper
// that builds a Remove carries the ones it rests on inside the Commit's
// authenticated data (MLSCommitEvidence), so every receiver verifies the same
// bytes without asking the server.

package proto

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

const (
	// ChatMLSErrorCodeStatementUnverified — a signed statement handed to
	// mls_commit_build does not verify. Nothing was built.
	ChatMLSErrorCodeStatementUnverified = "CHAT_MLS_STATEMENT_UNVERIFIED"

	// ChatMLSErrorCodeRolesUnsupported — a member's leaf or KeyPackage does not
	// advertise the room roles extension, which a group carrying roles
	// requires of every leaf. That member's Keeper must update. Nothing was
	// built.
	ChatMLSErrorCodeRolesUnsupported = "CHAT_MLS_ROLES_UNSUPPORTED"

	// MLSRoleOwner / MLSRoleAdmin are the listed roles. A member is anyone
	// holding a leaf and is not listed.
	MLSRoleOwner = "owner"
	MLSRoleAdmin = "admin"

	MLSRolesKindRoom = "room"
	MLSRolesKindDM   = "dm"

	// MLSStatementMaxPerKind bounds each statement list in one request and in
	// one Commit's authenticated data.
	MLSStatementMaxPerKind = ChatStateMaxPendingRemovals

	// MLSAccountPublicKeyMaxBytes bounds an admin public key PEM.
	MLSAccountPublicKeyMaxBytes = 4096

	orgRemovalDomain   = "dragpass.org.member.removal"
	chatLeaveDomain    = "dragpass.chat.leave"
	deviceRevokeDomain = "dragpass.mls.device.revoke"
	statementVersion   = "1"

	// MLSCommitEvidenceVersion is the version of the authenticated data
	// layout.
	MLSCommitEvidenceVersion = 1
)

// MLSRoleEntry is one listed account.
type MLSRoleEntry struct {
	AccountID string `json:"account_id"`
	Role      string `json:"role"`
}

// MLSRoleSet is a complete role list: a room's owner and admins, or a DM with
// none.
type MLSRoleSet struct {
	Kind    string         `json:"kind"`
	Entries []MLSRoleEntry `json:"entries"`
}

func (r MLSRoleSet) Validate(field string) error {
	switch r.Kind {
	case MLSRolesKindDM:
		if len(r.Entries) != 0 {
			return newValidationError(field+".entries", "a DM carries no roles")
		}
		return nil
	case MLSRolesKindRoom:
	default:
		return newValidationError(field+".kind", "must be room or dm")
	}
	if len(r.Entries) == 0 || len(r.Entries) > MLSStatementMaxPerKind {
		return newValidationError(field+".entries", "must hold 1.."+strconv.Itoa(MLSStatementMaxPerKind)+" entries")
	}
	owners := 0
	seen := map[string]bool{}
	for _, e := range r.Entries {
		if err := requireMessageUUID(e.AccountID, field+".entries.account_id"); err != nil {
			return err
		}
		if seen[e.AccountID] {
			return newValidationError(field+".entries", "must not name one account twice")
		}
		seen[e.AccountID] = true
		switch e.Role {
		case MLSRoleOwner:
			owners++
		case MLSRoleAdmin:
		default:
			return newValidationError(field+".entries.role", "must be owner or admin")
		}
	}
	if owners != 1 {
		return newValidationError(field+".entries", "a room has exactly one owner")
	}
	return nil
}

// MLSStatementMaxAgeSeconds is how long an org removal or a leave stays valid
// after the time it was signed at (removed_at, requested_at), read against the
// verifying Keeper's clock, at build and on receipt alike (Q10). A statement
// names an account and not an epoch, so without it a server could re-serve an
// old statement against an account that came back, forever; the window bounds
// that replay to 30 days. A statement dated ahead of the clock is not refused:
// only its signer can date it, and a signer can sign a fresh one anyway, so a
// future date lets nobody but the signer extend anything.
const MLSStatementMaxAgeSeconds = 30 * 24 * 60 * 60

// MLSStatementExpired reports whether a statement signed at signedAt is past
// the window at now (Unix seconds).
func MLSStatementExpired(signedAt, now int64) bool {
	return now-signedAt > MLSStatementMaxAgeSeconds
}

// MLSOrgRemovalStatement is an org admin's signed statement that an account
// was removed from the organization (Q5 (b)). AdminPublicKey is the admin's
// account public key PEM as the server serves it; the Keeper holds it to its
// pin for the admin account.
type MLSOrgRemovalStatement struct {
	OrgID            string `json:"org_id"`
	RemovedAccountID string `json:"removed_account_id"`
	AdminAccountID   string `json:"admin_account_id"`
	RemovedAt        int64  `json:"removed_at"`
	Signature        string `json:"signature"`
	AdminPublicKey   string `json:"admin_public_key,omitempty"`
}

// MLSOrgRemovalCanonical is what the admin signs:
//
//	dragpass.org.member.removal|1|<org_id>|<removed_account_id>|<admin_account_id>|<removed_at>
func MLSOrgRemovalCanonical(s MLSOrgRemovalStatement) string {
	return strings.Join([]string{
		orgRemovalDomain, statementVersion, s.OrgID, s.RemovedAccountID, s.AdminAccountID,
		strconv.FormatInt(s.RemovedAt, 10),
	}, "|")
}

func (s MLSOrgRemovalStatement) Validate(field string, needKey bool) error {
	for _, f := range []struct{ name, id string }{
		{".org_id", s.OrgID}, {".removed_account_id", s.RemovedAccountID}, {".admin_account_id", s.AdminAccountID},
	} {
		if err := requireMessageUUID(f.id, field+f.name); err != nil {
			return err
		}
	}
	if s.RemovedAt <= 0 {
		return newValidationError(field+".removed_at", "must be a positive Unix time")
	}
	if err := requireString(s.Signature, field+".signature"); err != nil {
		return err
	}
	if needKey && (s.AdminPublicKey == "" || len(s.AdminPublicKey) > MLSAccountPublicKeyMaxBytes) {
		return newValidationError(field+".admin_public_key", "must be the admin's public key PEM")
	}
	return nil
}

// MLSLeaveStatement is a member's signed request to leave a conversation
// (Q13).
type MLSLeaveStatement struct {
	ConversationID string `json:"conversation_id"`
	AccountID      string `json:"account_id"`
	RequestedAt    int64  `json:"requested_at"`
	Signature      string `json:"signature"`
}

// MLSLeaveCanonical is what the member signs:
//
//	dragpass.chat.leave|1|<conversation_id>|<account_id>|<requested_at>
func MLSLeaveCanonical(s MLSLeaveStatement) string {
	return strings.Join([]string{
		chatLeaveDomain, statementVersion, s.ConversationID, s.AccountID, strconv.FormatInt(s.RequestedAt, 10),
	}, "|")
}

func (s MLSLeaveStatement) Validate(field string) error {
	if err := requireMessageUUID(s.ConversationID, field+".conversation_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(s.AccountID, field+".account_id"); err != nil {
		return err
	}
	if s.RequestedAt <= 0 {
		return newValidationError(field+".requested_at", "must be a positive Unix time")
	}
	return requireString(s.Signature, field+".signature")
}

// MLSDeviceRef names one leaf by the account and device of its credential.
type MLSDeviceRef struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
}

// MLSDeviceRevocation is an account's signed revocation of one of its
// devices' leaves (Q13).
type MLSDeviceRevocation struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	RevokedAt int64  `json:"revoked_at"`
	Signature string `json:"signature"`
}

// MLSDeviceRevocationCanonical is what the account signs:
//
//	dragpass.mls.device.revoke|1|<account_id>|<device_id>|<revoked_at>
func MLSDeviceRevocationCanonical(s MLSDeviceRevocation) string {
	return strings.Join([]string{
		deviceRevokeDomain, statementVersion, s.AccountID, s.DeviceID, strconv.FormatInt(s.RevokedAt, 10),
	}, "|")
}

func (s MLSDeviceRevocation) Validate(field string) error {
	if err := requireMessageUUID(s.AccountID, field+".account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(s.DeviceID, field+".device_id"); err != nil {
		return err
	}
	if s.RevokedAt <= 0 {
		return newValidationError(field+".revoked_at", "must be a positive Unix time")
	}
	return requireString(s.Signature, field+".signature")
}

// MLSCommitEvidence is the one document a Commit's authenticated data holds:
// the signed statements its Removes rest on (wave 5a) and the leaf handovers
// its successions rest on (wave 5b). Both rules read it through
// DecodeMLSCommitEvidence, so data one of them wrote is never taken for
// "nothing" by the other. Canonical JSON is not required: the bytes are
// covered by the committer's signature as they are, and every receiver parses
// them.
type MLSCommitEvidence struct {
	V                 int                      `json:"v"`
	OrgRemovals       []MLSOrgRemovalStatement `json:"org_removals,omitempty"`
	Leaves            []MLSLeaveStatement      `json:"leaves,omitempty"`
	DeviceRevocations []MLSDeviceRevocation    `json:"device_revocations,omitempty"`
	Handovers         []MLSLeafHandover        `json:"handovers,omitempty"`
}

// MLSCommitEvidenceMaxHandovers bounds the handovers one Commit carries.
const MLSCommitEvidenceMaxHandovers = 32

// MLSCommitEvidenceMaxBytes bounds the document before it is parsed. It is
// the library edge's bound too (session.rs MAX_COMMIT_AUTHENTICATED_DATA), and
// holds every list at its limit with the largest admin key allowed.
const MLSCommitEvidenceMaxBytes = 1 << 20

// Empty reports whether the evidence carries nothing.
func (e MLSCommitEvidence) Empty() bool {
	return len(e.OrgRemovals) == 0 && len(e.Leaves) == 0 && len(e.DeviceRevocations) == 0 &&
		len(e.Handovers) == 0
}

// Encode is the authenticated data bytes, or nil when there is nothing.
func (e MLSCommitEvidence) Encode() ([]byte, error) {
	if e.Empty() {
		return nil, nil
	}
	if err := e.bounded(); err != nil {
		return nil, err
	}
	e.V = MLSCommitEvidenceVersion
	out, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(out) > MLSCommitEvidenceMaxBytes {
		return nil, newValidationError("authenticated_data", "is too large")
	}
	return out, nil
}

// DecodeMLSCommitEvidence reads a Commit's authenticated data. Empty data is
// no evidence. Anything else must be exactly a document Encode could have
// written: an unknown field, another version, trailing bytes, a list past its
// bound or a handover that is malformed is an error, and a receiver refuses
// the Commit rather than read it as carrying nothing.
func DecodeMLSCommitEvidence(aad []byte) (MLSCommitEvidence, error) {
	var e MLSCommitEvidence
	if len(aad) == 0 {
		return e, nil
	}
	if len(aad) > MLSCommitEvidenceMaxBytes {
		return MLSCommitEvidence{}, newValidationError("authenticated_data", "is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(aad))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return MLSCommitEvidence{}, err
	}
	if dec.More() {
		return MLSCommitEvidence{}, newValidationError("authenticated_data", "holds more than one document")
	}
	if e.V != MLSCommitEvidenceVersion {
		return MLSCommitEvidence{}, newValidationError("authenticated_data.v", "unknown evidence version")
	}
	if e.Empty() {
		return MLSCommitEvidence{}, newValidationError("authenticated_data", "is a document that carries nothing")
	}
	if err := e.bounded(); err != nil {
		return MLSCommitEvidence{}, err
	}
	return e, nil
}

func (e MLSCommitEvidence) bounded() error {
	if len(e.OrgRemovals) > MLSStatementMaxPerKind || len(e.Leaves) > MLSStatementMaxPerKind ||
		len(e.DeviceRevocations) > MLSStatementMaxPerKind {
		return newValidationError("authenticated_data", "too many statements")
	}
	if len(e.Handovers) > MLSCommitEvidenceMaxHandovers {
		return newValidationError("authenticated_data.handovers", "too many handovers")
	}
	for _, h := range e.Handovers {
		if err := h.Validate("authenticated_data.handovers"); err != nil {
			return err
		}
	}
	return nil
}

func validateStatements(orgs []MLSOrgRemovalStatement, leaves []MLSLeaveStatement, revs []MLSDeviceRevocation) error {
	if len(orgs) > MLSStatementMaxPerKind || len(leaves) > MLSStatementMaxPerKind || len(revs) > MLSStatementMaxPerKind {
		return newValidationError("statements", "at most "+strconv.Itoa(MLSStatementMaxPerKind)+" of each kind")
	}
	for _, s := range orgs {
		if err := s.Validate("org_removal_statements", true); err != nil {
			return err
		}
	}
	for _, s := range leaves {
		if err := s.Validate("leave_statements"); err != nil {
			return err
		}
	}
	for _, s := range revs {
		if err := s.Validate("device_revocations"); err != nil {
			return err
		}
	}
	return nil
}

func validateDeviceRefs(refs []MLSDeviceRef, field string) error {
	if len(refs) == 0 || len(refs) > MLSChatMaxRemoveAccounts {
		return newValidationError(field, "must hold 1.."+strconv.Itoa(MLSChatMaxRemoveAccounts)+" devices")
	}
	seen := map[MLSDeviceRef]bool{}
	for _, r := range refs {
		if err := requireMessageUUID(r.AccountID, field+".account_id"); err != nil {
			return err
		}
		if err := requireMessageUUID(r.DeviceID, field+".device_id"); err != nil {
			return err
		}
		if seen[r] {
			return newValidationError(field, "must not name one device twice")
		}
		seen[r] = true
	}
	return nil
}

// MLSLeaveRequestSignRequest asks for this device's signed leave request.
type MLSLeaveRequestSignRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
}

func (r MLSLeaveRequestSignRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSLeaveRequestSignRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

type MLSLeaveRequestSignResponseData struct {
	Statement MLSLeaveStatement `json:"statement"`
}

// OrgMemberRemovalSignRequest asks this device, an org admin's, to sign the
// removal of an account from the organization.
type OrgMemberRemovalSignRequest struct {
	OrgID            string `json:"org_id"`
	RemovedAccountID string `json:"removed_account_id"`
	AdminAccountID   string `json:"admin_account_id"`
}

func (r OrgMemberRemovalSignRequest) Validate() error {
	if err := requireMessageUUID(r.OrgID, "org_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.RemovedAccountID, "removed_account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AdminAccountID, "admin_account_id"); err != nil {
		return err
	}
	if r.RemovedAccountID == r.AdminAccountID {
		return newValidationError("removed_account_id", "an admin does not remove itself")
	}
	return nil
}

type OrgMemberRemovalSignResponseData struct {
	Statement MLSOrgRemovalStatement `json:"statement"`
}

// MLSDeviceRevokeSignRequest asks this device to sign the revocation of one
// of its account's devices.
type MLSDeviceRevokeSignRequest struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
}

func (r MLSDeviceRevokeSignRequest) Validate() error {
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	return requireMessageUUID(r.DeviceID, "device_id")
}

type MLSDeviceRevokeSignResponseData struct {
	Statement MLSDeviceRevocation `json:"statement"`
}
