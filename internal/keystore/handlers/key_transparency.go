package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
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
