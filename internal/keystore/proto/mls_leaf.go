// mls_leaf.go — the MLS leaf declaration (chat v2, form A).
//
// A declaration is how an account vouches for one of its devices' MLS leaf
// signature keys. It is signed with the account identity key, the key peers
// already pin, so accepting a leaf becomes a question the pin state machine
// already answers instead of a new root of trust.
//
// Every field names a device, not an account. Only one leaf per account exists
// today, but a verifier never learns that from this format.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.2, §5.3, §12.2.

package proto

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const (
	// MLSLeafCanonicalDomain keeps a declaration signature from verifying as
	// any other `dragpass.` statement signed by the same account key.
	MLSLeafCanonicalDomain = "dragpass.mls.leaf"

	// Version 2 added not_after. A version 1 declaration is refused wherever
	// one is met: it has no end, and a leaf key that never expires is what the
	// validity window exists to rule out.
	MLSLeafCanonicalVersion = 2

	// There is no revoke: a `rotate` declaration supersedes the previous one
	// for the same device (M1.5). There is no renew either: re-declaring before
	// not_after is a rotate with a new key.
	MLSLeafReasonEnroll = "enroll"
	MLSLeafReasonRotate = "rotate"

	// MLSLeafMaxValiditySeconds bounds not_after - not_before. 30 days is a
	// starting value, shared with ariadne, not a measured one.
	MLSLeafMaxValiditySeconds = 2592000

	// MLSLeafTreeGraceSeconds is how long after a Keeper first accepts an
	// account's newer declaration it still takes that account's older leaf in
	// a Welcome's tree. The window is for the rotating device to replace its
	// leaf in its existing groups with an Update Commit. 7 days is a starting
	// value, not a measured one.
	MLSLeafTreeGraceSeconds = 604800
)

// MLSLeafDeclaration is the signed statement as it crosses the wire.
// SignatureKey is the raw 32-byte Ed25519 public key in standard Base64, so the
// fingerprint is recomputable from the declaration alone.
type MLSLeafDeclaration struct {
	AccountID               string `json:"account_id"`
	DeviceID                string `json:"device_id"`
	SignatureKey            string `json:"signature_key"`
	SignatureKeyFingerprint string `json:"signature_key_fingerprint"`
	NotBefore               int64  `json:"not_before"`
	NotAfter                int64  `json:"not_after"`
	Reason                  string `json:"reason"`
	Signature               string `json:"signature"`
}

func (d MLSLeafDeclaration) Canonical() string {
	return MLSLeafCanonical(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter, d.Reason)
}

// MLSLeafCanonical renders the signing string. ariadne pins the same bytes.
//
//	dragpass.mls.leaf|2|<account_id>|<device_id>|<signature_key_fingerprint>|<not_before_unix>|<not_after_unix>|<reason>
func MLSLeafCanonical(accountID, deviceID, fingerprint string, notBefore, notAfter int64, reason string) string {
	return strings.Join([]string{
		MLSLeafCanonicalDomain,
		strconv.Itoa(MLSLeafCanonicalVersion),
		accountID,
		deviceID,
		fingerprint,
		strconv.FormatInt(notBefore, 10),
		strconv.FormatInt(notAfter, 10),
		reason,
	}, "|")
}

// Validate checks structure only. Whether the key hashes to the fingerprint
// and the signature verifies is VerifyMLSLeafDeclaration's job.
func (d MLSLeafDeclaration) Validate() error {
	if err := requireMessageUUID(d.AccountID, "leaf_declaration.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(d.DeviceID, "leaf_declaration.device_id"); err != nil {
		return err
	}
	if err := requireString(d.SignatureKey, "leaf_declaration.signature_key"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(d.SignatureKeyFingerprint, "leaf_declaration.signature_key_fingerprint"); err != nil {
		return err
	}
	if err := requireMLSLeafValidity(d.NotBefore, d.NotAfter, "leaf_declaration."); err != nil {
		return err
	}
	if err := requireMLSLeafReason(d.Reason, "leaf_declaration.reason"); err != nil {
		return err
	}
	return requireString(d.Signature, "leaf_declaration.signature")
}

// requireMLSLeafValidity is the window rule both sides apply: not_before
// strictly before not_after, and at most MLSLeafMaxValiditySeconds apart.
func requireMLSLeafValidity(notBefore, notAfter int64, prefix string) error {
	if err := requireRotatedAt(notBefore, prefix+"not_before"); err != nil {
		return err
	}
	if err := requireRotatedAt(notAfter, prefix+"not_after"); err != nil {
		return err
	}
	if notAfter <= notBefore {
		return newValidationError(prefix+"not_after", "must be after not_before")
	}
	if notAfter-notBefore > MLSLeafMaxValiditySeconds {
		return newValidationError(prefix+"not_after", "must be at most 30 days after not_before")
	}
	return nil
}

// MLSLeafDeclareRequest asks the Keeper to mint a leaf signature key for this
// device — the first one (enroll) or a replacement (rotate) — and to sign a
// declaration for it. The key and its declaration land in the pending slot;
// nothing active changes until mls_leaf_promote.
//
// DeviceID is the Extension's X-Device-ID, the id the server already keys this
// device's refresh tokens and request-signing key by. The Keeper has no device
// identity of its own to offer instead.
type MLSLeafDeclareRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	ServerSignature  string `json:"server_signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"`
	AccountID        string `json:"account_id"`
	DeviceID         string `json:"device_id"`
	NotBefore        int64  `json:"not_before"`
	NotAfter         int64  `json:"not_after"`
	Reason           string `json:"reason"`
}

func (r MLSLeafDeclareRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.ServerSignature, "server_signature"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.DeviceID, "device_id"); err != nil {
		return err
	}
	if err := requireMLSLeafValidity(r.NotBefore, r.NotAfter, ""); err != nil {
		return err
	}
	return requireMLSLeafReason(r.Reason, "reason")
}

// The challenge ariadne issues from POST /account/mls-leaves/challenge for one
// declaration. Parsing it is what binds the gate to this purpose: the server
// signature alone would accept any token the server has ever signed.
//
//	dragpass.mls.leaf.challenge|1|<account_id>|<device_id>|<nonce>|<expires_at_unix>
const (
	MLSLeafChallengeDomain     = "dragpass.mls.leaf.challenge"
	MLSLeafChallengeVersion    = 1
	MLSLeafChallengeTTLSeconds = 300
)

type MLSLeafChallenge struct {
	AccountID string
	DeviceID  string
	Nonce     string
	ExpiresAt int64
}

// ParseMLSLeafChallenge accepts only the exact bytes the issuer produces, so a
// token has one spelling. Single use is the server's to enforce: it consumes
// the nonce together with the declaration write.
func ParseMLSLeafChallenge(token string) (MLSLeafChallenge, error) {
	return parsePurposeChallenge(token, MLSLeafChallengeDomain, MLSLeafChallengeVersion,
		newValidationError("challenge_token", "is not an mls leaf challenge"))
}

func parsePurposeChallenge(token, domain string, version int, invalid error) (MLSLeafChallenge, error) {
	parts := strings.Split(token, "|")
	if len(parts) != 6 || parts[0] != domain || parts[1] != strconv.Itoa(version) {
		return MLSLeafChallenge{}, invalid
	}
	if requireMessageUUID(parts[2], "challenge_token") != nil ||
		requireMessageUUID(parts[3], "challenge_token") != nil ||
		requireKeyFingerprint(parts[4], "challenge_token") != nil {
		return MLSLeafChallenge{}, invalid
	}
	expiresAt, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil || expiresAt <= 0 || strconv.FormatInt(expiresAt, 10) != parts[5] {
		return MLSLeafChallenge{}, invalid
	}
	return MLSLeafChallenge{AccountID: parts[2], DeviceID: parts[3], Nonce: parts[4], ExpiresAt: expiresAt}, nil
}

type MLSLeafDeclareResponseData struct {
	MLSLeafDeclaration
}

// ─── mls_leaf_promote / mls_leaf_abort / mls_leaf_status ───────────────────

// The acceptance ariadne signs once it has stored a declaration. It names the
// declaration by everything a verifier would compare, so the Keeper can tell
// whether it is the pending entry, the active one, or neither.
//
//	dragpass.mls.leaf.accepted|1|<account_id>|<device_id>|<signature_key_fingerprint>|<not_before_unix>|<not_after_unix>
const (
	MLSLeafAcceptedDomain  = "dragpass.mls.leaf.accepted"
	MLSLeafAcceptedVersion = 1
)

type MLSLeafAccepted struct {
	AccountID   string
	DeviceID    string
	Fingerprint string
	NotBefore   int64
	NotAfter    int64
}

// Names reports whether the acceptance is for exactly this declaration. The
// reason is not part of the token and not compared: the key and its window
// already identify one declaration.
func (a MLSLeafAccepted) Names(d MLSLeafDeclaration) bool {
	return a.AccountID == d.AccountID && a.DeviceID == d.DeviceID &&
		a.Fingerprint == d.SignatureKeyFingerprint &&
		a.NotBefore == d.NotBefore && a.NotAfter == d.NotAfter
}

func MLSLeafAcceptedToken(accountID, deviceID, fingerprint string, notBefore, notAfter int64) string {
	return strings.Join([]string{
		MLSLeafAcceptedDomain,
		strconv.Itoa(MLSLeafAcceptedVersion),
		accountID,
		deviceID,
		fingerprint,
		strconv.FormatInt(notBefore, 10),
		strconv.FormatInt(notAfter, 10),
	}, "|")
}

// ParseMLSLeafAccepted accepts only the exact bytes MLSLeafAcceptedToken
// produces, so no second spelling can name the same declaration.
func ParseMLSLeafAccepted(token string) (MLSLeafAccepted, error) {
	invalid := newValidationError("acceptance_token", "is not an mls leaf acceptance")
	parts := strings.Split(token, "|")
	if len(parts) != 7 || parts[0] != MLSLeafAcceptedDomain || parts[1] != strconv.Itoa(MLSLeafAcceptedVersion) {
		return MLSLeafAccepted{}, invalid
	}
	if requireMessageUUID(parts[2], "acceptance_token") != nil ||
		requireMessageUUID(parts[3], "acceptance_token") != nil ||
		requireKeyFingerprint(parts[4], "acceptance_token") != nil {
		return MLSLeafAccepted{}, invalid
	}
	notBefore, ok := parseCanonicalUnix(parts[5])
	if !ok {
		return MLSLeafAccepted{}, invalid
	}
	notAfter, ok := parseCanonicalUnix(parts[6])
	if !ok || requireMLSLeafValidity(notBefore, notAfter, "") != nil {
		return MLSLeafAccepted{}, invalid
	}
	return MLSLeafAccepted{
		AccountID: parts[2], DeviceID: parts[3], Fingerprint: parts[4], NotBefore: notBefore, NotAfter: notAfter,
	}, nil
}

// parseCanonicalUnix reads a positive decimal with no sign, padding or
// leading zero, the only spelling strconv.FormatInt produces.
func parseCanonicalUnix(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || strconv.FormatInt(v, 10) != s {
		return 0, false
	}
	return v, true
}

// MLSLeafPromoteRequest carries ariadne's acceptance of the pending
// declaration and the server signature over it.
type MLSLeafPromoteRequest struct {
	AcceptanceToken  string `json:"acceptance_token"`
	ServerSignature  string `json:"server_signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"`
}

func (r MLSLeafPromoteRequest) Validate() error {
	if err := requireString(r.AcceptanceToken, "acceptance_token"); err != nil {
		return err
	}
	return requireString(r.ServerSignature, "server_signature")
}

// MLSLeafPromoteResponseData — Promoted is false only for a duplicate promote,
// one whose token names the entry that is already active.
type MLSLeafPromoteResponseData struct {
	Promoted    bool   `json:"promoted"`
	Fingerprint string `json:"signature_key_fingerprint"`
}

type MLSLeafAbortRequest struct{}

func (r MLSLeafAbortRequest) Validate() error { return nil }

// MLSLeafAbortResponseData — Aborted is false when there was no pending entry.
type MLSLeafAbortResponseData struct {
	Aborted bool `json:"aborted"`
}

type MLSLeafStatusRequest struct{}

func (r MLSLeafStatusRequest) Validate() error { return nil }

// MLSLeafStatusResponseData names the entries by their signature key
// fingerprints and validity windows, and nothing else. HasActive is false for
// a record an older Keeper wrote, which no session will use; enroll replaces
// it.
//
// The pending window is there for the caller's decision, not the Keeper's:
// ariadne refuses a retried declaration once its not_before is more than 24
// hours old or its not_after has passed, and from then on the only way forward
// is mls_leaf_abort and a fresh declare. The Keeper never aborts on its own.
type MLSLeafStatusResponseData struct {
	HasActive          bool   `json:"has_active"`
	ActiveFingerprint  string `json:"active_signature_key_fingerprint"`
	ActiveNotAfter     int64  `json:"active_not_after"`
	HasPending         bool   `json:"has_pending"`
	PendingFingerprint string `json:"pending_signature_key_fingerprint"`
	PendingNotBefore   int64  `json:"pending_not_before"`
	PendingNotAfter    int64  `json:"pending_not_after"`
}

func requireMLSLeafReason(value, field string) error {
	switch value {
	case MLSLeafReasonEnroll, MLSLeafReasonRotate:
		return nil
	case "":
		return newValidationError(field, "must not be empty")
	default:
		return newValidationError(field, "must be enroll or rotate")
	}
}

// ─── the leaf declaration extension (L2) ───────────────────────────────────

const (
	// MLSLeafExtensionType is the LeafNode extension that carries a leaf
	// declaration. RFC 9420 §17.3 private-use range; the Rust side
	// (gate::LEAF_DECLARATION_EXTENSION) owns the number and says why.
	MLSLeafExtensionType = 0xF0D0

	MLSLeafExtensionVersion = 1

	// MLSLeafExtensionMaxBytes bounds the payload before it is parsed. An
	// RSA-4096 PEM is about 800 bytes and the declaration about 500, so this
	// leaves room without letting a hostile leaf size a parse.
	MLSLeafExtensionMaxBytes = 8192
)

// MLSLeafExtension is the extension payload: the whole signed declaration and
// the account public key that signed it.
//
// The key rides along for first contact. A verifier with no pin for the
// account pins it on first use, which is the same trust the directory would
// have given; a verifier with a pin compares it against the pin, so carrying
// the key gives a server nothing it could not already try through the
// directory.
//
// AccountPublicKey is the PEM exactly as the account's Keeper stores it. The
// account fingerprint hashes those bytes, so they must reach the verifier
// untouched.
type MLSLeafExtension struct {
	V                int                `json:"v"`
	Declaration      MLSLeafDeclaration `json:"declaration"`
	AccountPublicKey string             `json:"account_public_key"`
}

// EncodeMLSLeafExtension is the one place the payload is serialized. The
// declaration is embedded as the struct it is, so a field added to the
// declaration reaches the payload, and the strict decoder on the other side,
// without either being edited.
func EncodeMLSLeafExtension(decl MLSLeafDeclaration, accountPublicKeyPEM string) ([]byte, error) {
	encoded, err := json.Marshal(MLSLeafExtension{
		V:                MLSLeafExtensionVersion,
		Declaration:      decl,
		AccountPublicKey: accountPublicKeyPEM,
	})
	if err != nil {
		return nil, err
	}
	if len(encoded) > MLSLeafExtensionMaxBytes {
		return nil, errors.New("mls leaf declaration extension exceeds its size bound")
	}
	return encoded, nil
}

// Validate is structural. Whether the declaration verifies, and against which
// key, is the leaf verifier's.
func (e MLSLeafExtension) Validate() error {
	if e.V != MLSLeafExtensionVersion {
		return newValidationError("leaf_extension.v", "is not a known version")
	}
	if err := requireString(e.AccountPublicKey, "leaf_extension.account_public_key"); err != nil {
		return err
	}
	return e.Declaration.Validate()
}

// ─── mls_key_package_generate ──────────────────────────────────────────────

// MLSKeyPackageGenerateMaxCount mirrors mls.MaxKeyPackagesPerCall; a test in
// the handlers package keeps them equal.
const MLSKeyPackageGenerateMaxCount = 32

// MLSKeyPackageGenerateRequest is gated like mls_leaf_declare: a server
// signature over a challenge bound to this purpose, account and device. Not a
// conversation-state permit — a device with no conversation yet needs
// KeyPackages to be added to its first one.
type MLSKeyPackageGenerateRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	ServerSignature  string `json:"server_signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"`
	AccountID        string `json:"account_id"`
	DeviceID         string `json:"device_id"`
	Count            int    `json:"count"`
}

func (r MLSKeyPackageGenerateRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.ServerSignature, "server_signature"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.DeviceID, "device_id"); err != nil {
		return err
	}
	if r.Count < 1 || r.Count > MLSKeyPackageGenerateMaxCount {
		return newValidationError("count", "must be between 1 and 32")
	}
	return nil
}

// The challenge ariadne issues for one mls_key_package_generate call and
// consumes with the upload it authorizes. Its own domain, so a leaf
// declaration challenge never opens this gate and this one never opens that.
//
//	dragpass.mls.keypackage.challenge|1|<account_id>|<device_id>|<nonce>|<expires_at_unix>
const (
	MLSKeyPackageChallengeDomain     = "dragpass.mls.keypackage.challenge"
	MLSKeyPackageChallengeVersion    = 1
	MLSKeyPackageChallengeTTLSeconds = 300
)

// ParseMLSKeyPackageChallenge accepts only the exact bytes the issuer
// produces, under the same rules as ParseMLSLeafChallenge.
func ParseMLSKeyPackageChallenge(token string) (MLSLeafChallenge, error) {
	return parsePurposeChallenge(token, MLSKeyPackageChallengeDomain, MLSKeyPackageChallengeVersion,
		newValidationError("challenge_token", "is not an mls key package challenge"))
}

// MLSKeyPackage is one KeyPackage (an MLSMessage, at most 8192 bytes) and the
// end of its lifetime in Unix seconds, which is the not_after the upload
// declares.
type MLSKeyPackage struct {
	KeyPackageB64 string `json:"key_package_b64"`
	NotAfter      uint64 `json:"not_after"`
}

// MLSKeyPackageGenerateResponseData carries public material only: each
// KeyPackage is something the server stores and hands out once.
//
// LeafSignatureKeyFingerprint names the leaf every KeyPackage was built for.
// The client passes it on upload, and the server refuses the batch unless it
// is the live declaration's fingerprint.
// MLSKeyPackagePoolSweepRequest names the owner whose pool is swept.
type MLSKeyPackagePoolSweepRequest struct {
	AccountID string `json:"account_id"`
}

func (r MLSKeyPackagePoolSweepRequest) Validate() error {
	return requireMessageUUID(r.AccountID, "account_id")
}

// MLSKeyPackagePoolSweepResponseData reports the entries dropped and those
// left in the pool.
type MLSKeyPackagePoolSweepResponseData struct {
	Dropped   int `json:"dropped"`
	Remaining int `json:"remaining"`
}

type MLSKeyPackageGenerateResponseData struct {
	KeyPackages                 []MLSKeyPackage `json:"key_packages"`
	LeafSignatureKeyFingerprint string          `json:"leaf_signature_key_fingerprint"`
}
