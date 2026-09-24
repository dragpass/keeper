// mls_chat.go — payload models for the MLS chat v2 actions.
//
// Every request here is a conversation-state request: it carries the same
// ChatStatePermit (canonical v4) as the chat_state_* actions and implements
// ChatStateBound, so the handlers run the one gate authorizeChatState already
// runs. What differs is the size cap, because a KeyPackage batch, a Commit and
// a Welcome are larger than one ciphertext.
//
// As in chat_state.go, Validate is structural only and there is no field that
// says how anything is bound: no AAD, no group id, no leaf index the caller
// picks. The group is named by the conversation, the leaf by the device's own
// key, and every position by the MLS state.
//
// Action rationale: actions_mls_chat.go. Design: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §12.2.

package proto

import (
	"math"
	"strconv"
	"strings"
)

// Domain error codes the MLS actions add. They ride in the envelope's
// `error_code` field next to the ChatState* and ChatMLS* codes in
// chat_state.go.
const (
	// ChatMLSErrorCodeCommitPending — this device has a Commit whose CAS
	// outcome it has not been told (design §7.3.2). A new Commit, a new send
	// and a new MLS open are refused until mls_commit_confirm settles it;
	// a retransmission and a history re-read are not.
	ChatMLSErrorCodeCommitPending = "CHAT_MLS_COMMIT_PENDING"

	// ChatMLSErrorCodeEpochStale — the request does not continue this device's
	// confirmed epoch: a send or Commit built for another epoch than the one
	// the group is on, or a handshake that is already applied or comes after
	// one that is not. The server answers its own CAS failure with the same
	// code; this is the Keeper-side meaning.
	ChatMLSErrorCodeEpochStale = "CHAT_MLS_EPOCH_STALE"

	// ChatMLSErrorCodeFailed — the MLS operation itself failed or refused: a
	// message that does not open, a declaration that does not match the
	// position, a Welcome for another conversation, a group state that does
	// not exist yet. Nothing was written.
	ChatMLSErrorCodeFailed = "CHAT_MLS_FAILED"

	// ChatMLSErrorCodeWelcomeUnusable — this device holds no private keys for
	// any KeyPackage the Welcome is addressed to: the KeyPackage expired, was
	// already used, or belonged to a leaf a promote has since replaced. The
	// invitation cannot be used on this device, and retrying cannot change
	// that; the member has to be invited again with a KeyPackage of the
	// current leaf. Nothing was written and the pool is unchanged.
	ChatMLSErrorCodeWelcomeUnusable = "CHAT_MLS_WELCOME_UNUSABLE"

	// ChatMLSErrorCodeCommitUnauthorized — a Commit this device was asked to
	// build carries an Add or a Remove the authority rules do not allow
	// (0.0.55). Nothing was built. A received Commit the rules refuse is not
	// this code: it latches the conversation (CHAT_STATE_REKEY_REQUIRED with
	// rekey_cause unauthorized_commit).
	ChatMLSErrorCodeCommitUnauthorized = "CHAT_MLS_COMMIT_UNAUTHORIZED"

	// ChatMLSErrorCodeRejoinUnverified — a rejoin in mls_commit_build carries
	// a request that is not the account's own signed statement for this
	// conversation and this KeyPackage's leaf, or one too old (0.0.55).
	// Nothing was built.
	ChatMLSErrorCodeRejoinUnverified = "CHAT_MLS_REJOIN_UNVERIFIED"
)

// Wire-shape constants. The ones that mirror a bound elsewhere are kept in
// step with it by a test in the handlers package, which can import both.
const (
	// MLSChatMaxMembersPerCommit mirrors mls.MaxKeyPackagesPerCall.
	MLSChatMaxMembersPerCommit = 32

	// MLSChatMaxKeyPackageBytes mirrors mls.MaxKeyPackageBytes, the largest
	// KeyPackage the server stores.
	MLSChatMaxKeyPackageBytes = 8192

	// MLSChatMaxCommitBytes mirrors chatstate.MaxCommitBytes, the bound on a
	// Commit and a Welcome.
	MLSChatMaxCommitBytes = 262144

	// MLSChatMaxRemoveAccounts bounds one Remove Commit. ariadne caps a room at
	// 30 members; the ceiling matches ChatStateMaxPendingRemovals.
	MLSChatMaxRemoveAccounts = ChatStateMaxPendingRemovals

	// MLSChatMaxRequestBytes is the cap for the membership and handshake
	// actions: 32 KeyPackages of 8192 bytes, or one 256 KiB Commit or
	// Welcome, in Base64, plus rotation chains and fixed context.
	MLSChatMaxRequestBytes = 1024 * 1024

	// MLSEncryptMaxPlaintextBytes bounds one application message. The
	// ciphertext has to fit the 8208 bytes the server's message column and
	// chatstate.MaxCiphertextBytes allow, and MLS adds the sender's signature,
	// the framing, the declaration and the AEAD tag, then pads with the
	// StepFunction rule (the top three bits of the length survive, so up to
	// an eighth more). 6144 bytes pads to at most 7168 and leaves the rest for
	// the overhead; a test in dispatch encrypts one of exactly this size.
	MLSEncryptMaxPlaintextBytes = 6144

	// MLSDecryptMaxMessages is the display batch cap. A larger batch is
	// refused rather than opened.
	MLSDecryptMaxMessages = 200

	// MLSDecryptMaxRequestBytes fits 200 ciphertexts of 8208 bytes in Base64
	// plus fixed context.
	MLSDecryptMaxRequestBytes = 3 * 1024 * 1024

	// MLSRoomNameMaxBytes mirrors chatstate.MaxRoomNameBytes: the server's
	// name_ciphertext column holds 272 bytes, the name and a 16-byte tag.
	MLSRoomNameMaxBytes = 256

	// MLSAppContextMaxBytes mirrors chatstate.MaxPendingAppContextBytes, the
	// bound on the app's description of a pending Commit (0.0.55).
	MLSAppContextMaxBytes = 65536

	// MLSRoomNameIVBytes is the AES-GCM IV of a sealed room name.
	MLSRoomNameIVBytes = 12

	// ConversationIVBytes / ConversationCiphertextMinBytes /
	// ConversationCiphertextMaxBytes — `ciphertext_b64` carries
	// ciphertext ‖ GCM tag, so its floor is a 1-byte message plus the 16-byte
	// tag and its ceiling matches the server's VARBINARY(8208) column.
	ConversationIVBytes            = 12
	ConversationCiphertextMinBytes = 17
	ConversationCiphertextMaxBytes = 8208
)

// validateRoomNamePlaintext bounds an optional room name input. The name
// rules (1..64 code points, no control characters) are the client's; the
// Keeper checks the size the server can store and, once decoded, UTF-8.
func validateAppContext(b64 string) error {
	if b64 == "" {
		return nil
	}
	return requireMessageBase64Len(b64, "app_context_b64", 1, MLSAppContextMaxBytes)
}

func validateRoomNamePlaintext(b64, field string, required bool) error {
	if b64 == "" && !required {
		return nil
	}
	return requireMessageBase64Len(b64, field, 1, MLSRoomNameMaxBytes)
}

// MLS commit outcomes a caller reports to mls_commit_confirm.
const (
	MLSCommitOutcomeAccepted   = "accepted"
	MLSCommitOutcomeSuperseded = "superseded"
	MLSCommitOutcomeUnknown    = "unknown"
)

// MLSMemberKeyPackage is one member to Add: the KeyPackage the server handed
// out, and the account and device the caller asked it for. The Keeper refuses
// a KeyPackage whose credential names anyone else, which §5.3 alone cannot
// catch: a server that answers a request for Bob with Mallory's valid
// KeyPackage passes every check a leaf is put through.
type MLSMemberKeyPackage struct {
	AccountID     string `json:"account_id"`
	DeviceID      string `json:"device_id"`
	KeyPackageB64 string `json:"key_package_b64"`
}

func (m MLSMemberKeyPackage) Validate() error {
	if err := requireMessageUUID(m.AccountID, "members.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(m.DeviceID, "members.device_id"); err != nil {
		return err
	}
	return requireMessageBase64Len(m.KeyPackageB64, "members.key_package_b64", 1, MLSChatMaxKeyPackageBytes)
}

func validateMLSMembers(members []MLSMemberKeyPackage, field string) error {
	if len(members) == 0 || len(members) > MLSChatMaxMembersPerCommit {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxMembersPerCommit)+" members")
	}
	seen := map[string]bool{}
	for _, m := range members {
		if err := m.Validate(); err != nil {
			return err
		}
		if seen[m.AccountID+"|"+m.DeviceID] {
			return newValidationError(field, "must not name one device twice")
		}
		seen[m.AccountID+"|"+m.DeviceID] = true
	}
	return nil
}

// MLSCommitResponseData is what mls_group_create and mls_commit_build hand
// back: the bytes to post to POST /:id/mls/commit. The Commit is pending and
// nothing about the confirmed state moved. WelcomeReleasable is always false
// here (RFC 9420 §14): the Welcome travels to the server with the Commit in
// one row and is served to a joiner only once that row won its epoch.
type MLSCommitResponseData struct {
	ClientCommitID string `json:"client_commit_id"`

	// ExpectedEpoch is the confirmed epoch the Commit was built against, the
	// value the server's CAS compares.
	ExpectedEpoch uint64 `json:"expected_epoch"`
	CommitB64     string `json:"commit_b64"`

	// WelcomeB64 is empty when the Commit adds nobody.
	WelcomeB64        string `json:"welcome_b64"`
	WelcomeReleasable bool   `json:"welcome_releasable"`

	// Created is false when the answer came from a Commit already pending
	// under the same client_commit_id: a lost response retried, not rebuilt.
	Created    bool   `json:"created"`
	Generation uint64 `json:"generation"`

	// NameEpoch / NameIVb64 / NameCiphertextB64 are the request's
	// room_name_plaintext_b64 sealed for the epoch this Commit creates, for
	// POST /:id/mls/commit to store with it. Absent when no name was given.
	NameEpoch         uint64 `json:"name_epoch,omitempty"`
	NameIVb64         string `json:"name_iv_b64,omitempty"`
	NameCiphertextB64 string `json:"name_ciphertext_b64,omitempty"`

	// LeafTrust is how this build judged the accounts its Add or replace
	// brings in (0.0.55). Absent for a Remove or an Update, and for a retry
	// answered from the stored Commit, which judges nothing.
	LeafTrust []MLSAccountTrust `json:"leaf_trust,omitempty"`
}

// MLS account trust states: the peer-key pin states (keychain.PeerKeyPinState)
// as the Keeper judged an account's key for a leaf of it.
const (
	MLSAccountTrustTOFU     = "tofu"
	MLSAccountTrustVerified = "verified"
	MLSAccountTrustRotated  = "rotated"
	MLSAccountTrustChanged  = "changed"
)

// MLSAccountTrust is the Keeper's judgement of one account's key, sorted by
// account id wherever it appears. On a response that brings leaves in it is
// the verdict the leaf verifier reached for every account it let in: tofu,
// verified or rotated, never changed, because a changed key is refused
// (CHAT_MLS_LEAF_UNTRUSTED) and nothing enters. On mls_conversation_status it
// is every account of the confirmed tree held against the pin as it now
// stands, where changed can appear. This account's own leaves are never
// listed, and neither is an account with no pin: the Keeper has nothing to
// judge it by, and the app must not show it as a first use.
type MLSAccountTrust struct {
	AccountID string `json:"account_id"`
	State     string `json:"state"`
}

// MLSGroupCreateRequest creates the conversation's group at epoch 0 and builds
// the Add for its first members. The caller is not in Members.
type MLSGroupCreateRequest struct {
	Permit             ChatStatePermit        `json:"permit"`
	OrgID              string                 `json:"org_id"`
	ConversationID     string                 `json:"conversation_id"`
	ClientCommitID     string                 `json:"client_commit_id"`
	Members            []MLSMemberKeyPackage  `json:"members"`
	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`

	// RoomNamePlaintextB64 is a room's name, resealed for epoch 1 in the
	// response. Omitted for a DM. Encrypt direction; zeroized after sealing.
	RoomNamePlaintextB64 string `json:"room_name_plaintext_b64,omitempty"`

	// AppContextB64 is kept with the pending Commit and comes back in
	// mls_conversation_status (0.0.55); see MLSCommitBuildRequest.
	AppContextB64 string `json:"app_context_b64,omitempty"`
}

func (r MLSGroupCreateRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSGroupCreateRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	if err := validateMLSMembers(r.Members, "members"); err != nil {
		return err
	}
	if err := validateRoomNamePlaintext(r.RoomNamePlaintextB64, "room_name_plaintext_b64", false); err != nil {
		return err
	}
	if err := validateAppContext(r.AppContextB64); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

// MLSGroupDiscardUnacceptedRequest drops this device's own group create whose
// create Commit the server gave to another device, so a Welcome to the
// winner's group can be joined.
type MLSGroupDiscardUnacceptedRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	ClientCommitID string          `json:"client_commit_id"`
}

func (r MLSGroupDiscardUnacceptedRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSGroupDiscardUnacceptedRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	return requireMessageUUID(r.ClientCommitID, "client_commit_id")
}

// MLSGroupDiscardUnacceptedResponseData — Discarded is false when there was
// no group left to drop and nothing was written.
type MLSGroupDiscardUnacceptedResponseData struct {
	Discarded  bool   `json:"discarded"`
	Generation uint64 `json:"generation"`
}

// MLSConversationForgetRemovedRequest drops the group state of a conversation
// this device was removed from.
type MLSConversationForgetRemovedRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
}

func (r MLSConversationForgetRemovedRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSConversationForgetRemovedRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

// MLSConversationForgetRemovedResponseData — Forgotten is false when there
// was no group left to drop and nothing was written.
type MLSConversationForgetRemovedResponseData struct {
	Forgotten  bool   `json:"forgotten"`
	Generation uint64 `json:"generation"`
}

// MLSReplaceMember is one account to replace (design M4.4): the account a new
// device took over, and that device's KeyPackage as the server handed it out.
// There is no fingerprint field: the only key the Keeper accepts for the
// account is the one the permit names in pending_leaf_replacements.
type MLSReplaceMember struct {
	AccountID     string `json:"account_id"`
	KeyPackageB64 string `json:"key_package_b64"`
}

// validateMLSReplace bounds the list like an Add, allows one entry per account,
// and requires every account to be one this request's permit lists as taken
// over. An account it does not list has no key the Keeper could accept.
func validateMLSReplace(members []MLSReplaceMember, listed []ChatStateLeafReplacement) error {
	const field = "replace"
	if len(members) == 0 || len(members) > MLSChatMaxMembersPerCommit {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxMembersPerCommit)+" accounts")
	}
	seen := map[string]bool{}
	for _, m := range members {
		if err := requireMessageUUID(m.AccountID, "replace.account_id"); err != nil {
			return err
		}
		if err := requireMessageBase64Len(m.KeyPackageB64, "replace.key_package_b64", 1, MLSChatMaxKeyPackageBytes); err != nil {
			return err
		}
		if seen[m.AccountID] {
			return newValidationError(field, "must not name one account twice")
		}
		seen[m.AccountID] = true
		if _, ok := LeafReplacementFor(listed, m.AccountID); !ok {
			return newValidationError(field, "names an account the permit does not list in pending_leaf_replacements")
		}
	}
	return nil
}

// LeafReplacementFor finds the permit's entry for an account.
func LeafReplacementFor(listed []ChatStateLeafReplacement, accountID string) (ChatStateLeafReplacement, bool) {
	for _, e := range listed {
		if e.AccountID == accountID {
			return e, true
		}
	}
	return ChatStateLeafReplacement{}, false
}

// MLSRejoinStatement is an account's own signed request to be re-seated in a
// conversation whose every Welcome it could not use (0.0.55, design Q6):
// which device asks, the leaf key its KeyPackages carry, and when. The
// signature is the account key's RSA-PSS SHA-256 over
// MLSRejoinStatementCanonical. It is a signed statement in the style of the
// leaf declaration, not a protocol of its own.
type MLSRejoinStatement struct {
	ConversationID          string `json:"conversation_id"`
	AccountID               string `json:"account_id"`
	DeviceID                string `json:"device_id"`
	SignatureKeyFingerprint string `json:"signature_key_fp"`
	RequestedAt             int64  `json:"requested_at"`
	Signature               string `json:"signature"`
}

// MLSRejoinStatementDomain / MLSRejoinStatementVersion — the first two slots
// of the rejoin canonical.
const (
	MLSRejoinStatementDomain  = "dragpass.mls.rejoin"
	MLSRejoinStatementVersion = 1

	// MLSRejoinStatementMaxAgeSeconds is how long a signed rejoin request is
	// honoured. Not measured: a request waits for another member to come
	// online, and a bound keeps a server from replaying one indefinitely.
	MLSRejoinStatementMaxAgeSeconds = 30 * 24 * 60 * 60
)

// MLSRejoinStatementCanonical is the signed string:
//
//	dragpass.mls.rejoin|1|<conversation_id>|<account_id>|<device_id>|<signature_key_fp>|<requested_at>
func MLSRejoinStatementCanonical(s MLSRejoinStatement) string {
	return strings.Join([]string{
		MLSRejoinStatementDomain,
		strconv.Itoa(MLSRejoinStatementVersion),
		s.ConversationID,
		s.AccountID,
		s.DeviceID,
		s.SignatureKeyFingerprint,
		strconv.FormatInt(s.RequestedAt, 10),
	}, "|")
}

func (s MLSRejoinStatement) Validate() error {
	if err := requireMessageUUID(s.ConversationID, "rejoin.request.conversation_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(s.AccountID, "rejoin.request.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(s.DeviceID, "rejoin.request.device_id"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(s.SignatureKeyFingerprint, "rejoin.request.signature_key_fp"); err != nil {
		return err
	}
	if err := requireMessageTimestamp(s.RequestedAt, "rejoin.request.requested_at"); err != nil {
		return err
	}
	_, err := requireBase64(s.Signature, "rejoin.request.signature")
	return err
}

// MLSRejoinMember is one account to re-seat: its KeyPackage as the server
// handed it out and its signed request. Every leaf the account holds goes out
// and this KeyPackage comes in, in one Commit.
type MLSRejoinMember struct {
	AccountID     string             `json:"account_id"`
	DeviceID      string             `json:"device_id"`
	KeyPackageB64 string             `json:"key_package_b64"`
	Request       MLSRejoinStatement `json:"request"`
}

func validateMLSRejoin(members []MLSRejoinMember, conversationID string) error {
	const field = "rejoin"
	if len(members) == 0 || len(members) > MLSChatMaxMembersPerCommit {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxMembersPerCommit)+" accounts")
	}
	seen := map[string]bool{}
	for _, m := range members {
		if err := requireMessageUUID(m.AccountID, "rejoin.account_id"); err != nil {
			return err
		}
		if err := requireMessageUUID(m.DeviceID, "rejoin.device_id"); err != nil {
			return err
		}
		if err := requireMessageBase64Len(m.KeyPackageB64, "rejoin.key_package_b64", 1, MLSChatMaxKeyPackageBytes); err != nil {
			return err
		}
		if err := m.Request.Validate(); err != nil {
			return err
		}
		if m.Request.AccountID != m.AccountID || m.Request.DeviceID != m.DeviceID ||
			m.Request.ConversationID != conversationID {
			return newValidationError(field, "request must name this account, device and conversation")
		}
		if seen[m.AccountID] {
			return newValidationError(field, "must not name one account twice")
		}
		seen[m.AccountID] = true
	}
	return nil
}

// MLSCommitAbandonRequest drops a pending Commit built before 0.0.55, which
// carries no app_context_b64, on the user's confirmation (design Q23). The
// caller has read the handshake log first: no row at the pending Commit's
// epoch + 1.
type MLSCommitAbandonRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	ClientCommitID string          `json:"client_commit_id"`
}

func (r MLSCommitAbandonRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitAbandonRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	return requireMessageUUID(r.ClientCommitID, "client_commit_id")
}

// MLSCommitAbandonResponseData is the record's write counter after the drop.
type MLSCommitAbandonResponseData struct {
	Generation uint64 `json:"generation"`
}

// MLSRejoinRequestSignRequest asks for this device's signed rejoin request
// for the conversation (0.0.55). The permit binds it to the account.
type MLSRejoinRequestSignRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
}

func (r MLSRejoinRequestSignRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSRejoinRequestSignRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

// MLSRejoinRequestSignResponseData is the signed request, to post to the
// server as it is.
type MLSRejoinRequestSignResponseData struct {
	Request MLSRejoinStatement `json:"request"`
}

// MLSCommitAttestation is the server's signature over the member set a
// handshake row's Commit declared (0.0.55): which accounts the conversation
// holds once that Commit is applied, bound to the Commit's own bytes. It is
// the evidence the authority rules read for R3b, and never for an Add. It is
// server-attested: 임시, 정책 미충족 (Q5).
type MLSCommitAttestation struct {
	MemberAccountIDs []string `json:"member_account_ids"`
	ServerKeyVersion uint     `json:"server_key_version"`
	Signature        string   `json:"signature"`
}

// MLSCommitAttestationDomain / MLSCommitAttestationVersion — the first two
// slots of the attestation canonical.
const (
	MLSCommitAttestationDomain  = "dragpass.chat.commit"
	MLSCommitAttestationVersion = 1
)

// MLSCommitAttestationCanonical is the signed string:
//
//	dragpass.chat.commit|1|<conversation_id>|<epoch>|<commit_sha256_hex>|<member_account_ids>|<server_key_version>
//
// member_account_ids is lowercase UUIDs sorted ascending and joined with ",".
func MLSCommitAttestationCanonical(conversationID string, epoch uint64, commitSHA256 string, a MLSCommitAttestation) string {
	return strings.Join([]string{
		MLSCommitAttestationDomain,
		strconv.Itoa(MLSCommitAttestationVersion),
		conversationID,
		strconv.FormatUint(epoch, 10),
		commitSHA256,
		strings.Join(a.MemberAccountIDs, ","),
		strconv.FormatUint(uint64(a.ServerKeyVersion), 10),
	}, "|")
}

func (a MLSCommitAttestation) Validate(field string) error {
	if len(a.MemberAccountIDs) == 0 {
		return newValidationError(field+".member_account_ids", "must hold at least one account id")
	}
	if len(a.MemberAccountIDs) > ChatStateMaxPendingRemovals {
		return newValidationError(field+".member_account_ids", "holds too many account ids")
	}
	for i, id := range a.MemberAccountIDs {
		if err := requireMessageUUID(id, field+".member_account_ids"); err != nil {
			return err
		}
		if i > 0 && a.MemberAccountIDs[i-1] >= id {
			return newValidationError(field+".member_account_ids", "must be sorted ascending without duplicates")
		}
	}
	if a.ServerKeyVersion < 1 || a.ServerKeyVersion > math.MaxUint32 {
		return newValidationError(field+".server_key_version", "must be a positive uint32")
	}
	_, err := requireBase64(a.Signature, field+".signature")
	return err
}

// MLSCommitBuildRequest builds one Commit of exactly one kind: an Add, a
// Remove of every leaf of the named accounts, a replace of the named
// accounts' leaves with their new devices' (design M4.4), or an Update of this
// device's own leaf. UpdateSelf also moves the group onto the device's active
// leaf key when a rotation has promoted a new one (design P3).
type MLSCommitBuildRequest struct {
	Permit           ChatStatePermit       `json:"permit"`
	OrgID            string                `json:"org_id"`
	ConversationID   string                `json:"conversation_id"`
	ClientCommitID   string                `json:"client_commit_id"`
	ExpectedEpoch    uint64                `json:"expected_epoch"`
	Add              []MLSMemberKeyPackage `json:"add,omitempty"`
	RemoveAccountIDs []string              `json:"remove_account_ids,omitempty"`
	Replace          []MLSReplaceMember    `json:"replace,omitempty"`
	Rejoin           []MLSRejoinMember     `json:"rejoin,omitempty"`
	UpdateSelf       bool                  `json:"update_self,omitempty"`

	// UserInitiated says a person on this device asked for this add or
	// remove_account_ids (0.0.55). Automation never sends it. An add needs it;
	// a remove needs it unless the permit names every account as departed.
	// It is the app's word: 임시, 정책 미충족 (Q3) until room roles live in the
	// authenticated group context.
	UserInitiated bool `json:"user_initiated,omitempty"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`

	// RoomNamePlaintextB64 is the room's name as this device last opened it,
	// resealed for the epoch the Commit creates. Omitted for a DM. Encrypt
	// direction; zeroized after sealing.
	RoomNamePlaintextB64 string `json:"room_name_plaintext_b64,omitempty"`

	// AppContextB64 is the app's own description of the Commit, opaque to the
	// Keeper and not a secret by contract (0.0.55). It is stored with the
	// pending Commit, a retry under the same id keeps the first one, and
	// mls_conversation_status returns it while the Commit is pending: an app
	// that lost its own note of the Commit reposts it from there instead of
	// leaving the conversation pending for good.
	AppContextB64 string `json:"app_context_b64,omitempty"`
}

func (r MLSCommitBuildRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitBuildRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	// Epoch 0 is a group whose creating Add is still pending, and a pending
	// Commit refuses another; nothing is ever built against it. Requiring a
	// positive value also keeps the assertion from being skipped by a zero.
	if r.ExpectedEpoch < 1 {
		return newValidationError("expected_epoch", "must be a positive epoch")
	}
	kinds := 0
	if r.Add != nil {
		kinds++
		if err := validateMLSMembers(r.Add, "add"); err != nil {
			return err
		}
	}
	if r.RemoveAccountIDs != nil {
		kinds++
		if err := validateRemoveAccounts(r.RemoveAccountIDs); err != nil {
			return err
		}
	}
	if r.Replace != nil {
		kinds++
		if err := validateMLSReplace(r.Replace, r.Permit.PendingLeafReplacements); err != nil {
			return err
		}
	}
	if r.Rejoin != nil {
		kinds++
		if err := validateMLSRejoin(r.Rejoin, r.ConversationID); err != nil {
			return err
		}
	}
	if r.UpdateSelf {
		kinds++
	}
	if r.UserInitiated && r.Add == nil && r.RemoveAccountIDs == nil {
		return newValidationError("user_initiated", "is only for add and remove_account_ids")
	}
	if kinds != 1 {
		return newValidationError("add",
			"exactly one of add, remove_account_ids, replace, rejoin and update_self must be given")
	}
	if err := validateRoomNamePlaintext(r.RoomNamePlaintextB64, "room_name_plaintext_b64", false); err != nil {
		return err
	}
	if err := validateAppContext(r.AppContextB64); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

func validateRemoveAccounts(ids []string) error {
	const field = "remove_account_ids"
	if len(ids) == 0 || len(ids) > MLSChatMaxRemoveAccounts {
		return newValidationError(field,
			"must hold 1.."+strconv.Itoa(MLSChatMaxRemoveAccounts)+" account ids")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if err := requireMessageUUID(id, field); err != nil {
			return err
		}
		if seen[id] {
			return newValidationError(field, "must not name one account twice")
		}
		seen[id] = true
	}
	return nil
}

// MLSCommitConfirmRequest reports what the server's CAS said about a Commit
// this device built. Outcome is accepted, superseded (another Commit won the
// epoch; WinnerCommitB64 is that Commit), or unknown (the response was lost
// and the caller is about to ask the server by client_commit_id). Unknown
// writes nothing and answers with the bytes to repost.
type MLSCommitConfirmRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientCommitID  string          `json:"client_commit_id"`
	Outcome         string          `json:"outcome"`
	WinnerCommitB64 string          `json:"winner_commit_b64,omitempty"`

	// WinnerAttestation is the winning row's commit_attestation, for a
	// superseded outcome (0.0.55). Absent when the row carried none.
	WinnerAttestation *MLSCommitAttestation `json:"winner_attestation,omitempty"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSCommitConfirmRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSCommitConfirmRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientCommitID, "client_commit_id"); err != nil {
		return err
	}
	switch r.Outcome {
	case MLSCommitOutcomeSuperseded:
		if err := requireMessageBase64Len(
			r.WinnerCommitB64, "winner_commit_b64", 1, MLSChatMaxCommitBytes,
		); err != nil {
			return err
		}
		if r.WinnerAttestation != nil {
			if err := r.WinnerAttestation.Validate("winner_attestation"); err != nil {
				return err
			}
		}
	case MLSCommitOutcomeAccepted, MLSCommitOutcomeUnknown:
		if r.WinnerCommitB64 != "" || r.WinnerAttestation != nil {
			return newValidationError("winner_commit_b64", "is only for a superseded outcome")
		}
	default:
		return newValidationError("outcome", "must be "+MLSCommitOutcomeAccepted+", "+
			MLSCommitOutcomeSuperseded+" or "+MLSCommitOutcomeUnknown)
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

// MLSCommitConfirmResponseData is the state after the verdict. For accepted
// and superseded, Epoch is the new confirmed epoch; for unknown it is the one
// the pending Commit was built against, and CommitB64 is that Commit, to be
// reposted under the same client_commit_id if the server has no record of it.
type MLSCommitConfirmResponseData struct {
	Outcome           string `json:"outcome"`
	Epoch             uint64 `json:"epoch"`
	WelcomeReleasable bool   `json:"welcome_releasable"`
	Removed           bool   `json:"removed"`
	CommitB64         string `json:"commit_b64"`
	Generation        uint64 `json:"generation"`

	// LeafTrust is set when superseded applied a winner that brought
	// accounts in (0.0.55); see MLSAccountTrust.
	LeafTrust []MLSAccountTrust `json:"leaf_trust,omitempty"`

	// WinnerAddedAccountIDs / WinnerRemovedAccountIDs are the accounts the
	// winning Commit of a superseded outcome added and removed a leaf of
	// (0.0.55), so a caller whose Commit lost can stop when the winner touched
	// the accounts it was about (Q20). Absent otherwise.
	WinnerAddedAccountIDs   []string `json:"winner_added_account_ids,omitempty"`
	WinnerRemovedAccountIDs []string `json:"winner_removed_account_ids,omitempty"`
}

// MLSProcessRequest applies one handshake row from GET /:id/mls/handshake:
// somebody else's Commit. Epoch is the row's epoch, the one the Commit
// produced; the Keeper applies rows only in epoch order and checks the claim
// against what the Commit really produced.
type MLSProcessRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	Seq            uint64          `json:"seq"`
	Epoch          uint64          `json:"epoch"`
	CommitB64      string          `json:"commit_b64"`

	// CommitAttestation is the row's commit_attestation (0.0.55). Absent when
	// the row carried none, which the authority rules read as no evidence.
	CommitAttestation *MLSCommitAttestation `json:"commit_attestation,omitempty"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSProcessRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSProcessRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if r.Seq < 1 {
		return newValidationError("seq", "must be a positive sequence")
	}
	if r.Epoch < 1 {
		return newValidationError("epoch", "must be a positive epoch")
	}
	if err := requireMessageBase64Len(r.CommitB64, "commit_b64", 1, MLSChatMaxCommitBytes); err != nil {
		return err
	}
	if r.CommitAttestation != nil {
		if err := r.CommitAttestation.Validate("commit_attestation"); err != nil {
			return err
		}
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

type MLSProcessResponseData struct {
	Seq        uint64 `json:"seq"`
	Epoch      uint64 `json:"epoch"`
	Removed    bool   `json:"removed"`
	Generation uint64 `json:"generation"`

	// LeafTrust is how the Commit's entering accounts were judged (0.0.55);
	// absent when it brought none in. See MLSAccountTrust.
	LeafTrust []MLSAccountTrust `json:"leaf_trust,omitempty"`
}

// MLSJoinRequest joins the conversation's group from a Welcome addressed to
// one of this device's KeyPackages.
type MLSJoinRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	WelcomeB64     string          `json:"welcome_b64"`

	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r MLSJoinRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSJoinRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageBase64Len(r.WelcomeB64, "welcome_b64", 1, MLSChatMaxCommitBytes); err != nil {
		return err
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

type MLSJoinResponseData struct {
	Epoch uint64 `json:"epoch"`

	// LeafTrust is how every other account in the Welcome's tree was judged
	// (0.0.55). See MLSAccountTrust.
	LeafTrust []MLSAccountTrust `json:"leaf_trust,omitempty"`
}

// MLSEncryptRequest encrypts one application message: reserve, encrypt and
// persist in one locked section (design §7.2.1 T-c). client_message_id is the
// outbox key: a second call with it answers with the stored ciphertext and
// encrypts nothing.
type MLSEncryptRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientMessageID string          `json:"client_message_id"`
	ExpectedEpoch   uint64          `json:"expected_epoch"`
	PlaintextB64    string          `json:"plaintext_b64"` // encrypt direction; zeroized after sealing, never logged
}

func (r MLSEncryptRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSEncryptRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientMessageID, "client_message_id"); err != nil {
		return err
	}
	// Nothing is ever sent at epoch 0, where the creator is alone and its Add
	// is pending; a positive value also keeps the assertion from being
	// skipped by a zero.
	if r.ExpectedEpoch < 1 {
		return newValidationError("expected_epoch", "must be a positive epoch")
	}
	return requireMessageBase64Len(r.PlaintextB64, "plaintext_b64", 1, MLSEncryptMaxPlaintextBytes)
}

// MLSEncryptResponseData is what POST /:id/messages needs: the ciphertext, and
// the position the library actually used, which the sender declares for the
// W2 watermark. The caller does not pick the position; only the group state
// knows it. Generation here is the step along this sender's application
// ratchet, not the record's write counter.
type MLSEncryptResponseData struct {
	ClientMessageID string `json:"client_message_id"`
	CiphertextB64   string `json:"ciphertext_b64"`
	Epoch           uint64 `json:"epoch"`
	LeafIndex       uint32 `json:"leaf_index"`
	ContentType     string `json:"content_type"`
	Generation      uint64 `json:"generation"`

	// Created is false when the stored ciphertext for this client_message_id
	// answered: a retransmission sends the same bytes.
	Created bool `json:"created"`
}

// MLSMarkSentRequest binds a message this device sent to the seq the server
// gave it (POST /:id/messages), so later display batches answer it from the
// sealed local copy.
type MLSMarkSentRequest struct {
	Permit          ChatStatePermit `json:"permit"`
	OrgID           string          `json:"org_id"`
	ConversationID  string          `json:"conversation_id"`
	ClientMessageID string          `json:"client_message_id"`
	Seq             uint64          `json:"seq"`
}

func (r MLSMarkSentRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSMarkSentRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageUUID(r.ClientMessageID, "client_message_id"); err != nil {
		return err
	}
	if r.Seq < 1 {
		return newValidationError("seq", "must be a positive sequence")
	}
	return nil
}

// MLSMarkSentResponseData — Bound is false when the copy already carried this
// seq and nothing was written.
type MLSMarkSentResponseData struct {
	ClientMessageID string `json:"client_message_id"`
	Seq             uint64 `json:"seq"`
	Bound           bool   `json:"bound"`
	Generation      uint64 `json:"generation"`
}

// MLSDisplayMessage is one message of a display batch: the server's seq and
// the MLS PrivateMessage it stored.
type MLSDisplayMessage struct {
	Seq           uint64 `json:"seq"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// MLSDecryptBatchForAppDisplayRequest opens a page of one conversation's
// messages for display. It answers with MLSDisplayResponseData.
type MLSDecryptBatchForAppDisplayRequest struct {
	Permit         ChatStatePermit     `json:"permit"`
	OrgID          string              `json:"org_id"`
	ConversationID string              `json:"conversation_id"`
	Messages       []MLSDisplayMessage `json:"messages"`
}

func (r MLSDecryptBatchForAppDisplayRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSDecryptBatchForAppDisplayRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if len(r.Messages) == 0 || len(r.Messages) > MLSDecryptMaxMessages {
		return newValidationError("messages",
			"must hold 1.."+strconv.Itoa(MLSDecryptMaxMessages)+" entries")
	}
	seen := make(map[uint64]bool, len(r.Messages))
	for _, m := range r.Messages {
		if m.Seq < 1 {
			return newValidationError("messages.seq", "must be a positive sequence")
		}
		if seen[m.Seq] {
			return newValidationError("messages.seq", "must not repeat within a batch")
		}
		seen[m.Seq] = true
		if err := requireMessageBase64Len(
			m.CiphertextB64, "messages.ciphertext_b64", 1, ConversationCiphertextMaxBytes,
		); err != nil {
			return err
		}
	}
	return nil
}

// MLS display item states.
const (
	// MLSDisplayItemStateShown — the item's plaintext_b64 entry is the message.
	MLSDisplayItemStateShown = "shown"

	// MLSDisplayItemStateOwnWithoutCopy — this device sent the message and
	// holds no sealed copy for its seq. MLS never opens a message from its own
	// leaf, so there is no plaintext: plaintext_b64 is "" at this index, the
	// sender is this device, and the position fields are zero. The one outcome
	// that does not refuse the batch.
	MLSDisplayItemStateOwnWithoutCopy = "own_without_local_copy"

	// MLSDisplayItemStateHistoryUnavailable — this device already opened the
	// message once and no longer holds its sealed copy (the local history
	// evicted it), so it cannot be shown again: its MLS key was consumed at
	// that first delivery. plaintext_b64 is "" at this index, the sender and
	// position fields are empty and zero, and nothing was opened or written
	// for it. The batch proceeds (0.0.55).
	MLSDisplayItemStateHistoryUnavailable = "history_unavailable"

	// MLSDisplayItemStateBeforeJoin — the message belongs to an epoch before
	// the one this device's leaf entered the group at, so this device never
	// held its key. It is not an error and not lost history: nobody could
	// open it here. plaintext_b64 is "" at this index, the sender and position
	// fields are empty and zero, and nothing was opened or written for it.
	// The batch proceeds (0.0.55).
	MLSDisplayItemStateBeforeJoin = "before_join"
)

// MLSDisplayItem is what the app may show about one decrypted message besides
// its plaintext, parallel to plaintext_b64. The sender comes from the leaf
// credential MLS authenticated, never from the server; epoch, leaf, axis and
// generation are the position the declaration was checked against.
// FromHistory is true when the plaintext came from this device's sealed local
// copy and no MLS key was used; a message this device sent is always read
// that way. State says whether there is a plaintext at all.
type MLSDisplayItem struct {
	Seq             uint64 `json:"seq"`
	State           string `json:"state"`
	SenderAccountID string `json:"sender_account_id"`
	SenderDeviceID  string `json:"sender_device_id"`
	Epoch           uint64 `json:"epoch"`
	SenderLeafIndex uint32 `json:"sender_leaf_index"`
	ContentType     string `json:"content_type"`
	Generation      uint64 `json:"generation"`
	FromHistory     bool   `json:"from_history"`
}

// MLSRoomNameSealRequest seals a room's name under the confirmed epoch's
// exporter, for a rename or the epoch 0 name a room is created with.
type MLSRoomNameSealRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
	PlaintextB64   string          `json:"plaintext_b64"` // encrypt direction; zeroized after sealing, never logged
}

func (r MLSRoomNameSealRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSRoomNameSealRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	return validateRoomNamePlaintext(r.PlaintextB64, "plaintext_b64", true)
}

// MLSRoomNameSealResponseData is the server's name_iv / name_ciphertext and
// the epoch (name_epoch) whose exporter opens them.
type MLSRoomNameSealResponseData struct {
	Epoch             uint64 `json:"epoch"`
	NameIVb64         string `json:"name_iv_b64"`
	NameCiphertextB64 string `json:"name_ciphertext_b64"`
}

// MLSRoomNameOpenRequest opens a room's name for display. Epoch is the
// server's name_epoch and must be this device's confirmed epoch. The answer is
// MLSDisplayResponseData with one plaintext entry.
type MLSRoomNameOpenRequest struct {
	Permit            ChatStatePermit `json:"permit"`
	OrgID             string          `json:"org_id"`
	ConversationID    string          `json:"conversation_id"`
	Epoch             uint64          `json:"epoch"`
	NameIVb64         string          `json:"name_iv_b64"`
	NameCiphertextB64 string          `json:"name_ciphertext_b64"`
}

func (r MLSRoomNameOpenRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSRoomNameOpenRequest) Validate() error {
	if err := validateChatStateContext(r.Permit, r.OrgID, r.ConversationID); err != nil {
		return err
	}
	if err := requireMessageBase64Len(r.NameIVb64, "name_iv_b64", MLSRoomNameIVBytes, MLSRoomNameIVBytes); err != nil {
		return err
	}
	return requireMessageBase64Len(r.NameCiphertextB64, "name_ciphertext_b64", 17, MLSRoomNameMaxBytes+16)
}

// MLSConversationStatusRequest asks where this device's copy of the
// conversation stands. Read-only.
type MLSConversationStatusRequest struct {
	Permit         ChatStatePermit `json:"permit"`
	OrgID          string          `json:"org_id"`
	ConversationID string          `json:"conversation_id"`
}

func (r MLSConversationStatusRequest) ChatStateContext() (ChatStatePermit, string, string) {
	return r.Permit, r.OrgID, r.ConversationID
}

func (r MLSConversationStatusRequest) Validate() error {
	return validateChatStateContext(r.Permit, r.OrgID, r.ConversationID)
}

// Why a conversation is latched needs_rekey. The recovery is the same for all
// of them; they differ in what the user is told happened.
const (
	// ChatStateRekeyCauseRollback — the local state file is older than the
	// keyring anchor says it is: a restored backup or a copied file.
	ChatStateRekeyCauseRollback = "rollback_detected"

	// ChatStateRekeyCauseStateMissing — the state file is gone while the
	// anchor says it was used.
	ChatStateRekeyCauseStateMissing = "state_missing"

	// ChatStateRekeyCauseWatermarkAhead — the server says this device's own
	// leaf sent further than the local state knows.
	ChatStateRekeyCauseWatermarkAhead = "watermark_ahead"

	// ChatStateRekeyCauseAnchorUnreadable — the keyring anchor is unreadable.
	ChatStateRekeyCauseAnchorUnreadable = "anchor_unreadable"

	// ChatStateRekeyCauseUnknown — latched by a Keeper that did not record a
	// cause.
	ChatStateRekeyCauseUnknown = "unknown"

	// ChatStateRekeyCauseUnauthorizedCommit — a member's Commit carried an
	// Add or a Remove the authority rules do not allow, and this device
	// refused to apply it (0.0.55). rekey_epoch and rekey_committer_* name it.
	ChatStateRekeyCauseUnauthorizedCommit = "unauthorized_commit"

	// ChatStateRekeyCauseFork — the server served, for an epoch this device
	// already confirmed, another Commit than the one it applied (0.0.55).
	// rekey_epoch names the epoch.
	ChatStateRekeyCauseFork = "fork"
)

// MLSConversationStatusResponseData lets the app say "참여자 변경 반영 중"
// before it tries to send, rather than after a refusal. RemovalLatch is the
// accounts a send would be refused for now (CHAT_MLS_ROTATION_PENDING), judged
// on the confirmed roster against this permit's list; empty, never null.
// LeafReplacementLatch is the same for CHAT_MLS_LEAF_REPLACEMENT_PENDING, in
// the permit's entry shape. When
// NeedsRekey is true the record is latched for a rewind and the other fields
// are zero: nothing behind the latch is trusted to say anything.
type MLSConversationStatusResponseData struct {
	Epoch                 uint64   `json:"epoch"`
	HasGroupState         bool     `json:"has_group_state"`
	CommitPending         bool     `json:"commit_pending"`
	PendingClientCommitID string   `json:"pending_client_commit_id"`
	RemovalLatch          []string `json:"removal_latch_account_ids"`

	// PendingAppContextB64 is the app_context_b64 the pending Commit was built
	// with (0.0.55), absent when none is pending or it was built without one.
	PendingAppContextB64 string `json:"pending_app_context_b64,omitempty"`

	// PendingName* is the room name the pending Commit's first build sealed
	// (0.0.55), the name_* fields that build answered with; absent when it
	// sealed none.
	PendingNameEpoch         uint64 `json:"pending_name_epoch,omitempty"`
	PendingNameIVb64         string `json:"pending_name_iv_b64,omitempty"`
	PendingNameCiphertextB64 string `json:"pending_name_ciphertext_b64,omitempty"`

	LeafReplacementLatch []ChatStateLeafReplacement `json:"leaf_replacement_latch"`
	NeedsRekey           bool                       `json:"needs_rekey"`

	// RekeyCause says why needs_rekey latched (0.0.55): one of the
	// ChatStateRekeyCause* values, "unknown" for a latch recorded before the
	// cause was, and absent when needs_rekey is false.
	RekeyCause string `json:"rekey_cause,omitempty"`

	// RekeyEpoch and RekeyCommitter* are what an unauthorized_commit or fork
	// latch was about (0.0.55): the epoch the refused or conflicting Commit
	// produces, and for unauthorized_commit the committing leaf's account and
	// device as the group's own tree names them. Absent otherwise.
	RekeyEpoch              uint64 `json:"rekey_epoch,omitempty"`
	RekeyCommitterAccountID string `json:"rekey_committer_account_id,omitempty"`
	RekeyCommitterDeviceID  string `json:"rekey_committer_device_id,omitempty"`

	// RemovedFromGroup — the last Commit applied here removed this device, so
	// mls_conversation_forget_removed must run before mls_join (0.0.53).
	RemovedFromGroup bool `json:"removed_from_group"`

	// MemberTrust is every other account in the confirmed tree held against
	// its pin now (0.0.55); see MLSAccountTrust. Absent with needs_rekey, with
	// no group, and when the pins could not be read.
	MemberTrust []MLSAccountTrust `json:"member_trust,omitempty"`
}

// ChatStateRekeyLatchedData rides on CHAT_STATE_REKEY_REQUIRED from the
// operation that latched a conversation unauthorized_commit or fork (0.0.55),
// with the same fields mls_conversation_status reports.
type ChatStateRekeyLatchedData struct {
	RekeyCause              string `json:"rekey_cause"`
	RekeyEpoch              uint64 `json:"rekey_epoch"`
	RekeyCommitterAccountID string `json:"rekey_committer_account_id,omitempty"`
	RekeyCommitterDeviceID  string `json:"rekey_committer_device_id,omitempty"`
}

// MLSDisplayResponseData carries the decrypted payloads of
// mls_decrypt_batch_for_app_display, parallel to request.messages, or the one
// room name of mls_room_name_open.
//
// PlaintextB64 is the second TestNoRawSecretInResponseTypes carve-out (the
// first is 0.0.29's GroupDecryptWithAadForAppDisplayResponseData.plaintext_b64).
// See the carve-out comment in no_raw_secret_response_test.go and
// dragpass-control-plane docs/exec-plans/active/dragpass-chat-v2-mls-integration.md
// M6.3.
//
// Items is the metadata of each plaintext, parallel to PlaintextB64, and no
// plaintext of its own. mls_room_name_open leaves it out.
type MLSDisplayResponseData struct {
	PlaintextB64 []string         `json:"plaintext_b64"` // secret in RESPONSE — the approved chat carve-out; never logged
	Items        []MLSDisplayItem `json:"items,omitempty"`
}
