package handlers

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// Only the selected approver's archive key can open this attachment. The
// session signature is verified against the target captured before the API call.
type archiveRequesterProof struct {
	RequesterAccountID        string                         `json:"requester_account_id"`
	RequesterDeviceID         string                         `json:"requester_device_id"`
	RequesterAccountPublicKey string                         `json:"requester_account_public_key"`
	GroupID                   string                         `json:"group_id"`
	DekVersion                int                            `json:"dek_version"`
	SessionSignatureB64       string                         `json:"session_signature_b64"`
	BindingEvidence           proto.KeyTransparencyEvidence  `json:"binding_evidence"`
	EnrollmentEvidence        *proto.KeyTransparencyEvidence `json:"enrollment_evidence"`
	RotationStatements        []proto.KeyRotationStatement   `json:"rotation_statements"`
}

func verifiedArchiveRequester(d Deps, req proto.ArchiveShareRewrapRequest, private *rsa.PrivateKey) bool {
	envelope := req.Decision.RequesterProof
	target := req.RecoveryTarget
	trust, err := usableTrust(d)
	if envelope == nil || target == nil || err != nil || trust == nil || trust.ConfigDigest == "" {
		return false
	}
	plaintext, err := crypto.HybridUnwrap(private, envelope.WrappedKey, envelope.Ciphertext)
	if err != nil {
		return false
	}
	defer secure.Zeroize(plaintext)
	var p archiveRequesterProof
	if len(plaintext) > proto.ArchiveRequesterProofMaxBytes || json.Unmarshal(plaintext, &p) != nil || p.RequesterAccountID != target.RequesterAccountID || p.GroupID != target.GroupID || p.DekVersion != target.DekVersion {
		return false
	}

	statement, err := base64.StdEncoding.DecodeString(p.BindingEvidence.StatementB64)
	if err != nil {
		return false
	}
	binding, err := keytransparency.VerifyAccountStatement(statement, target.RequesterAccountID)
	accountFingerprint := crypto.AccountKeyFingerprint([]byte(p.RequesterAccountPublicKey))
	if err != nil || binding.SourceType != keytransparency.StatementDeviceRequestKeyBinding || binding.DeviceID != p.RequesterDeviceID || binding.AccountKeyFingerprint != accountFingerprint {
		return false
	}
	if !p.verifiesSession(req, binding.DevicePublicKey) {
		return false
	}
	if _, err := keytransparency.VerifyAndPersistEvidence(d.Store, *trust, p.BindingEvidence, statement); err != nil {
		return false
	}
	return p.verifyAccountForRelease(d, req.AccountID, accountFingerprint)
}

func (p *archiveRequesterProof) verifiesSession(req proto.ArchiveShareRewrapRequest, deviceKey string) bool {
	device, err := base64.StdEncoding.DecodeString(deviceKey)
	if err != nil || len(device) != ed25519.PublicKeySize {
		return false
	}
	spki, err := crypto.RewrapKeyFingerprint(req.SessionPublicKey)
	if err != nil {
		return false
	}
	scope := proto.ArchiveRecoverySessionKeyProof{SessionID: &req.RecoverySessionID, OrgID: req.OrgID, GroupID: req.RecoveryTarget.GroupID, DekVersion: req.RecoveryTarget.DekVersion, SessionSPKI: spki}
	sig, err := base64.StdEncoding.DecodeString(p.SessionSignatureB64)
	return err == nil && ed25519.Verify(device, []byte(scope.Canonical(req.RecoveryTarget.RequesterAccountID, p.RequesterDeviceID, spki)), sig)

}

func (p *archiveRequesterProof) verifyAccountForRelease(d Deps, owner, accountFingerprint string) bool {
	evaluation := proto.PeerKeyChainEvaluateRequest{OwnerAccountID: owner, AccountID: p.RequesterAccountID, PublicKey: p.RequesterAccountPublicKey, RequireTransparency: true, EnrollmentEvidence: p.EnrollmentEvidence, RotationStatements: p.RotationStatements}
	if evaluation.Validate() != nil {
		return false
	}
	if _, ok := requirePeerKeyOwner(d, owner); !ok {
		return false
	}
	existing, err := loadPeerKeyPin(d.Store, owner, p.RequesterAccountID)
	if err != nil {
		return false
	}
	outcome, err := evaluatePeerKeyWithProof(d, evaluation, existing, accountFingerprint)
	if err != nil || !outcome.Allowed || !enrollmentRooted(d, &outcome.Pin, owner, p.RequesterAccountID) {
		return false
	}
	strict, err := requireVerifiedPeers(d)
	if err != nil {
		return false
	}
	self := owner == p.RequesterAccountID && isOwnActiveKey(d, accountFingerprint)
	if !applyPeerKeyPolicy(outcome, strict && !self).Allowed {
		return false
	}
	return keychain.SavePeerKeyPin(d.Store, owner, p.RequesterAccountID, outcome.Pin) == nil
}
