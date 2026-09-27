package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"

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
	return proto.BaseResponse{Success: false, Error: keyTransparencyRefusalMessage(code), ErrorCode: code}
}

const (
	keyTransparencyCodeUnverified   = "key_transparency_unverified"
	keyTransparencyCodeFork         = "key_transparency_fork"
	keyTransparencyCodeTrustInvalid = "key_transparency_trust_invalid"
)

func keyTransparencyErrorCode(err error) string {
	if errors.Is(err, keytransparency.ErrTrustInvalid) {
		return keyTransparencyCodeTrustInvalid
	}
	if errors.Is(err, keytransparency.ErrCheckpointFork) || errors.Is(err, keytransparency.ErrCheckpointRollback) || errors.Is(err, keytransparency.ErrConsistencyProof) {
		return keyTransparencyCodeFork
	}
	return keyTransparencyCodeUnverified
}

func keyTransparencyRefusalMessage(code string) string {
	if code == keyTransparencyCodeTrustInvalid {
		return "key transparency trust file is present but unusable; key changes are refused"
	}
	return "key transparency proof could not be verified"
}
