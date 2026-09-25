// mls_leaf_handover.go — the old device's approval of a device takeover
// (0.0.55, design §0.3 policy 1, Q1).
//
// The statement is signed with the old device's leaf signing key, the key
// every group tree holds for it, so a peer's Keeper verifies it against the
// authenticated tree and not against anything a server hands out. The
// canonical, the window and the rule that consumes it live in
// chatstate/succession.go; this file is the wire shape.

package proto

// ChatMLSErrorCodeHandoverInvalid — a leaf handover does not verify, names
// another succession than the one it is offered for, or, at signing, is asked
// for a declaration this device's account key did not sign, for this device
// itself, or for a request whose window has closed. Nothing was signed or
// built.
const ChatMLSErrorCodeHandoverInvalid = "CHAT_MLS_HANDOVER_INVALID"

// MLSLeafHandoverMaxSeconds mirrors chatstate.HandoverMaxSeconds (a test in
// handlers keeps them equal): the ten-minute request window of design Q1.
const MLSLeafHandoverMaxSeconds = 600

// MLSLeafHandover is the signed statement as it crosses the wire. Signature is
// the raw 64-byte Ed25519 signature in standard Base64.
type MLSLeafHandover struct {
	AccountID         string `json:"account_id"`
	OldDeviceID       string `json:"old_device_id"`
	OldSignatureKeyFP string `json:"old_signature_key_fingerprint"`
	NewDeviceID       string `json:"new_device_id"`
	NewSignatureKeyFP string `json:"new_signature_key_fingerprint"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
	Signature         string `json:"signature"`
}

// Validate is structural. Whether it verifies, and for which leaves, is the
// succession rule's.
func (h MLSLeafHandover) Validate(field string) error {
	for _, f := range []struct{ v, name string }{
		{h.AccountID, ".account_id"}, {h.OldDeviceID, ".old_device_id"}, {h.NewDeviceID, ".new_device_id"},
	} {
		if err := requireMessageUUID(f.v, field+f.name); err != nil {
			return err
		}
	}
	if err := requireKeyFingerprint(h.OldSignatureKeyFP, field+".old_signature_key_fingerprint"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(h.NewSignatureKeyFP, field+".new_signature_key_fingerprint"); err != nil {
		return err
	}
	if err := requireRotatedAt(h.IssuedAt, field+".issued_at"); err != nil {
		return err
	}
	if err := requireRotatedAt(h.ExpiresAt, field+".expires_at"); err != nil {
		return err
	}
	if h.ExpiresAt < h.IssuedAt || h.ExpiresAt-h.IssuedAt > MLSLeafHandoverMaxSeconds {
		return newValidationError(field+".expires_at", "must be at most 600 seconds after issued_at")
	}
	sig, err := requireBase64(h.Signature, field+".signature")
	if err != nil {
		return err
	}
	if len(sig) != 64 {
		return newValidationError(field+".signature", "must be a 64-byte Ed25519 signature")
	}
	return nil
}

// MLSLeafHandoverSignRequest asks this device, the one whose leaf is in the
// account's groups, to approve new_declaration taking its seat. expires_at is
// the takeover request's own expiry as the server relayed it; the Keeper
// refuses one that has passed or lies further out than the window allows.
type MLSLeafHandoverSignRequest struct {
	AccountID      string             `json:"account_id"`
	NewDeclaration MLSLeafDeclaration `json:"new_declaration"`
	ExpiresAt      int64              `json:"expires_at"`
}

func (r MLSLeafHandoverSignRequest) Validate() error {
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := r.NewDeclaration.Validate(); err != nil {
		return err
	}
	return requireRotatedAt(r.ExpiresAt, "expires_at")
}

type MLSLeafHandoverSignResponseData struct {
	Handover MLSLeafHandover `json:"handover"`
}
