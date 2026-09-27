package handlers

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func requireKeyTransparency(d Deps) bool {
	return d.RequireKeyTransparency || d.KeyTransparencyTrust != nil
}

func verifyRotationTransparency(d Deps, statements []proto.KeyRotationStatement) error {
	if len(statements) == 0 || !requireKeyTransparency(d) {
		return nil
	}
	if d.KeyTransparencyTrust == nil {
		return keytransparency.ErrTrustUnavailable
	}
	for _, statement := range statements {
		if statement.TransparencyEvidence == nil {
			return keytransparency.ErrInvalidCheckpoint
		}
		canonical, err := keytransparency.EncodeAccountKeyRotationStatement(statement)
		if err != nil {
			return keytransparency.ErrInvalidCheckpoint
		}
		if _, err := keytransparency.VerifyAndPersistEvidence(d.Store, *d.KeyTransparencyTrust, *statement.TransparencyEvidence, canonical); err != nil {
			return err
		}
	}
	return nil
}

func verifyMLSLeafTransparency(d Deps, evidence []proto.KeyTransparencyEvidence, declaration proto.MLSLeafDeclaration, accountPublicKey string) error {
	if !requireKeyTransparency(d) {
		return nil
	}
	if d.KeyTransparencyTrust == nil {
		return keytransparency.ErrTrustUnavailable
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
		_, err := keytransparency.VerifyAndPersistEvidence(d.Store, *d.KeyTransparencyTrust, candidate, canonical)
		return err
	}
	return keytransparency.ErrInvalidCheckpoint
}

func keyTransparencyRefusal(d Deps, err error) proto.BaseResponse {
	code := keyTransparencyErrorCode(err)
	d.Logger.Printf("key transparency verification refused a key change (%s)", code)
	return proto.BaseResponse{Success: false, Error: "key transparency proof could not be verified", ErrorCode: code}
}

func keyTransparencyErrorCode(err error) string {
	if errors.Is(err, keytransparency.ErrCheckpointFork) || errors.Is(err, keytransparency.ErrCheckpointRollback) || errors.Is(err, keytransparency.ErrConsistencyProof) {
		return "key_transparency_fork"
	}
	return "key_transparency_unverified"
}
