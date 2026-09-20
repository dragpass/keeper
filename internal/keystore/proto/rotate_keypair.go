// rotate_keypair_models.go — user RSA keypair voluntary rotation payloads.
// 4 types: Prepare/Promote + Status/Abort.

package proto

// ────────────────────────────────────────────────────────────────────────
// User RSA keypair voluntary rotation.
//
// 2-step: prepare (generate new keypair + sign with both) → the Extension
// goes through server verification to fetch a confirmation → promote
// (pending → active).
// ────────────────────────────────────────────────────────────────────────

// RotateUserKeypairPrepareRequest — the Extension sends the challenge it
// got from the server. challenge_token + server_signature verify the
// rotation origin.
// The three account key trust fields are required, not optional. A rotation
// that produced no statement would leave every peer holding a pin that no
// longer matches and nothing to explain it, which turns their next wrap into
// peer_key_changed — the failure mode the statement exists to prevent. So
// there is no path through this action that rotates without one.
type RotateUserKeypairPrepareRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	ServerSignature  string `json:"server_signature"`             // server signature over challenge_token
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
	// AccountID is the subject of the statement canonical.
	AccountID string `json:"account_id"`
	// Reason is voluntary or compromise, the caller's choice. `recovery`
	// is not selectable here: it belongs to the recovery flow, which sets it
	// itself, so no caller can label an ordinary rotation as a recovery.
	Reason string `json:"reason"`
	// RotatedAt is the Unix seconds the statement is dated, and part of what
	// both signatures cover.
	RotatedAt int64 `json:"rotated_at"`
}

func (r RotateUserKeypairPrepareRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.ServerSignature, "server_signature"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	switch r.Reason {
	case KeyRotationReasonVoluntary, KeyRotationReasonCompromise:
	case "":
		return newValidationError("reason", "must not be empty")
	default:
		return newValidationError("reason", "must be voluntary or compromise")
	}
	return requireRotatedAt(r.RotatedAt, "rotated_at")
}

// RotateUserKeypairPrepareResponseData — new public key + OLD/NEW
// signatures + the peer-verifiable rotation statement.
type RotateUserKeypairPrepareResponseData struct {
	NewPublicKey string `json:"new_public_key"` // PEM string (Extension Base64-encodes it when sending to the server)
	OldSignature string `json:"old_signature"`  // challenge signed by ACTIVE(OLD) priv, Base64
	NewSignature string `json:"new_signature"`  // challenge signed by PENDING(NEW) priv, Base64
	// RotationStatement is signed over the §5 canonical rather than over the
	// challenge. The two challenge signatures above prove key ownership to
	// the server and are untouched; this one proves the same thing to peers,
	// who never see the challenge and would have no reason to trust it if
	// they did.
	RotationStatement KeyRotationStatement `json:"rotation_statement"`
}

// RotateUserKeypairPromoteRequest — sent when the server approves
// rotation by issuing a confirmation.
type RotateUserKeypairPromoteRequest struct {
	ConfirmationToken     string `json:"confirmation_token"`
	ConfirmationPayload   string `json:"confirmation_payload"`   // structured payload the server signed
	ConfirmationSignature string `json:"confirmation_signature"` // server signature over confirmation_payload
	ServerKeyVersion      uint   `json:"server_key_version,omitempty"`
}

func (r RotateUserKeypairPromoteRequest) Validate() error {
	if err := requireString(r.ConfirmationToken, "confirmation_token"); err != nil {
		return err
	}
	if err := requireString(r.ConfirmationPayload, "confirmation_payload"); err != nil {
		return err
	}
	return requireString(r.ConfirmationSignature, "confirmation_signature")
}

type RotateUserKeypairPromoteResponseData struct {
	Promoted        bool   `json:"promoted"`
	ActivePublicKey string `json:"active_public_key"`
}

// ────────────────────────────────────────────────────────────────────────
// User keypair rotation partial-failure recovery.
//
// Diagnose / clean up stuck states (interrupted between prepare and
// promote).
// ────────────────────────────────────────────────────────────────────────

// RotateUserKeypairStatusRequest is an empty request — no side args.
type RotateUserKeypairStatusRequest struct{}

// Validate is always nil for empty requests.
func (r RotateUserKeypairStatusRequest) Validate() error { return nil }

// RotateUserKeypairStatusResponseData — state of the active/pending public
// keys in the Keychain.
//
//   - HasPending=true means the pending slot holds a private key (after
//     prepare, before promote).
//   - PendingPublicKey is meaningful only when HasPending=true; otherwise
//     it is the empty string.
//   - ActivePublicKey is the PEM of the active slot's public key (empty
//     string means signup hasn't happened).
type RotateUserKeypairStatusResponseData struct {
	HasPending       bool   `json:"has_pending"`
	PendingPublicKey string `json:"pending_public_key"`
	ActivePublicKey  string `json:"active_public_key"`
}

// RotateUserKeypairAbortRequest is an empty request.
type RotateUserKeypairAbortRequest struct{}

// Validate is always nil for empty requests.
func (r RotateUserKeypairAbortRequest) Validate() error { return nil }

// RotateUserKeypairAbortResponseData — pending-slot disposal result.
// Aborted=true means something was actually wiped from the pending
// private-key or public-key slot. false means both were already absent
// (idempotent call — normal).
type RotateUserKeypairAbortResponseData struct {
	Aborted bool `json:"aborted"`
}
