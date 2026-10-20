package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// usableTrust returns the trust to verify against when the gate requires
// transparency, or the configuration error that refuses the change instead.
func usableTrust(d Deps) (*keytransparency.Trust, error) {
	if d.KeyTransparency.ConfigErr != nil {
		return nil, d.KeyTransparency.ConfigErr
	}
	return d.KeyTransparency.Trust, nil
}

func verifyRotationTransparency(d Deps, statements []proto.KeyRotationStatement) error {
	if len(statements) == 0 || !d.KeyTransparency.Required() {
		return nil
	}
	trust, err := usableTrust(d)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if statement.TransparencyEvidence == nil {
			return keytransparency.ErrInvalidCheckpoint
		}
		canonical, err := keytransparency.EncodeAccountKeyRotationStatement(statement)
		if err != nil {
			return keytransparency.ErrInvalidCheckpoint
		}
		if _, err := keytransparency.VerifyAndPersistEvidence(d.Store, *trust, *statement.TransparencyEvidence, canonical); err != nil {
			return err
		}
	}
	return nil
}

func verifyAccountEnrollmentTransparency(
	d Deps,
	evidence *proto.KeyTransparencyEvidence,
	accountID string,
	publicKey string,
) error {
	if !d.KeyTransparency.Required() {
		return nil
	}
	trust, err := usableTrust(d)
	if err != nil {
		return err
	}
	if evidence == nil {
		return keytransparency.ErrInvalidCheckpoint
	}
	statement, err := base64.StdEncoding.DecodeString(evidence.StatementB64)
	if err != nil {
		return keytransparency.ErrInvalidCheckpoint
	}
	verified, err := keytransparency.VerifyAccountStatement(statement, accountID)
	if err != nil || verified.SourceType != keytransparency.StatementAccountKeyEnrollment ||
		verified.Fingerprint != crypto.AccountKeyFingerprint([]byte(publicKey)) {
		return keytransparency.ErrInvalidCheckpoint
	}
	_, err = keytransparency.VerifyAndPersistEvidence(d.Store, *trust, *evidence, statement)
	return err
}

// carryPeerKeyProof settles which log proof, if any, still stands behind the
// pin an allowed observation is about to persist. It never refuses; it only
// keeps the record honest:
//
//   - same key: a record for exactly this owner, account and key stays;
//   - a rotation (the state machine accepted a chain): with a trust file
//     configured every link was already proven by verifyRotationTransparency,
//     so the proof moves to the new key only if the key it started from was
//     itself proven. A chain from an unproven key proves nothing about the
//     account, and without a trust file no link was proven at all;
//   - anything else, including a first observation: no record.
func carryPeerKeyProof(d Deps, owner, account string, existing *keychain.PeerKeyPin, pin *keychain.PeerKeyPin) {
	rotated := existing != nil && existing.Fingerprint != pin.Fingerprint
	if rotated && d.KeyTransparency.Required() && existing.KeyTransparencyVerified(owner, account) {
		pin.KeyTransparency = peerKeyProofRecord(d, owner, account, pin.Fingerprint, keytransparency.StatementAccountKeyRotation)
		return
	}
	if rotated || !pin.KeyTransparencyVerified(owner, account) {
		pin.KeyTransparency = nil
	}
}

// requirePeerKeyProof is the wrap path's Key Transparency rule, applied to
// the pin an allowed observation is about to persist. With a trust file
// configured, the key that pin holds must have a verified log proof for this
// owner and account: one recorded earlier (carried by carryPeerKeyProof), or
// the enrollment proof the request carries for this exact account and key.
// Being pinned is not enough, because a pin can come from a Welcome tree, an
// org removal statement, a human comparison, or a Keeper that predates the
// record, and none of those consulted the log. Without a trust file nothing is
// required, as before.
func requirePeerKeyProof(
	d Deps, owner, account string, existing *keychain.PeerKeyPin, pin *keychain.PeerKeyPin,
	publicKey string, evidence *proto.KeyTransparencyEvidence,
) error {
	carryPeerKeyProof(d, owner, account, existing, pin)
	if !d.KeyTransparency.Required() || pin.KeyTransparencyVerified(owner, account) {
		return nil
	}
	if err := verifyAccountEnrollmentTransparency(d, evidence, account, publicKey); err != nil {
		return err
	}
	pin.KeyTransparency = peerKeyProofRecord(d, owner, account, pin.Fingerprint, keytransparency.StatementAccountKeyEnrollment)
	return nil
}

func peerKeyProofRecord(d Deps, owner, account, fingerprint, source string) *keychain.PeerKeyTransparency {
	return &keychain.PeerKeyTransparency{
		OwnerAccountID: owner, AccountID: account, Fingerprint: fingerprint,
		Source: source, VerifiedAt: d.Now().Unix(),
	}
}

func verifyMLSLeafTransparency(d Deps, evidence []proto.KeyTransparencyEvidence, declaration proto.MLSLeafDeclaration, accountPublicKey string) error {
	if !d.KeyTransparency.Required() {
		return nil
	}
	trust, err := usableTrust(d)
	if err != nil {
		return err
	}
	canonical, err := keytransparency.EncodeMLSLeafBindingStatement(declaration, accountPublicKey)
	if err != nil {
		return keytransparency.ErrInvalidCheckpoint
	}
	for _, candidate := range evidence {
		statement, decodeErr := base64.StdEncoding.DecodeString(candidate.StatementB64)
		if decodeErr != nil || !bytes.Equal(statement, canonical) {
			continue
		}
		_, err := keytransparency.VerifyAndPersistEvidence(d.Store, *trust, candidate, canonical)
		return err
	}
	return keytransparency.ErrInvalidCheckpoint
}

func keyTransparencyRefusal(d Deps, err error) proto.BaseResponse {
	code := keyTransparencyErrorCode(err)
	d.Logger.Printf("key transparency verification refused a key change (%s)", code)
	return errs.CodeResponse(code, keyTransparencyRefusalMessage(code))
}

func keyTransparencyErrorCode(err error) errs.ErrorCode {
	if errors.Is(err, keytransparency.ErrTrustInvalid) {
		return errs.ErrCodeKeyTransparencyTrustInvalid
	}
	if errors.Is(err, keytransparency.ErrCheckpointFork) || errors.Is(err, keytransparency.ErrCheckpointRollback) || errors.Is(err, keytransparency.ErrConsistencyProof) {
		return errs.ErrCodeKeyTransparencyFork
	}
	return errs.ErrCodeKeyTransparencyUnverified
}

func keyTransparencyRefusalMessage(code errs.ErrorCode) string {
	if code == errs.ErrCodeKeyTransparencyTrustInvalid {
		return "key transparency trust file is present but unusable; key changes are refused"
	}
	return "key transparency proof could not be verified"
}
