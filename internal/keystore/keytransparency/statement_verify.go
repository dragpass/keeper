package keytransparency

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	accountKeyEnrollmentStatementFieldCount = 4
	rotationStatementFieldCount             = 9
	mlsLeafStatementFieldCount              = 9
)

type VerifiedStatement struct {
	SourceType  string
	AccountID   string
	DeviceID    string
	Fingerprint string
	Reason      string
	Digest      string
}

func VerifyAccountStatement(statement []byte, expectedAccountID string) (VerifiedStatement, error) {
	var result VerifiedStatement
	if len(statement) == 0 || len(statement) > statementMaxBytes {
		return result, ErrInvalidCheckpoint
	}
	parts := strings.Split(string(statement), "|")
	if len(parts) < 3 || parts[0] != statementDomain || parts[1] != "1" {
		return result, ErrInvalidCheckpoint
	}
	fields := make([]string, len(parts)-3)
	for index, encoded := range parts[3:] {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return result, ErrInvalidCheckpoint
		}
		fields[index] = string(decoded)
	}
	switch parts[2] {
	case StatementAccountKeyEnrollment:
		if len(fields) != accountKeyEnrollmentStatementFieldCount || fields[0] != expectedAccountID {
			return result, ErrInvalidCheckpoint
		}
		fingerprint := fields[1]
		if !isLowerHexFingerprint(fingerprint) || crypto.AccountKeyFingerprint([]byte(fields[2])) != fingerprint {
			return result, ErrInvalidCheckpoint
		}
		canonical := proto.AccountKeyEnrollmentCanonical(fields[0], fingerprint)
		if err := verifyAccountSignatureBytes(fields[2], []byte(fields[3]), canonical); err != nil {
			return result, ErrInvalidCheckpoint
		}
		reencoded, err := EncodeAccountKeyEnrollmentStatement(fields[0], fingerprint, []byte(fields[2]), []byte(fields[3]))
		if err != nil || string(reencoded) != string(statement) {
			return result, ErrInvalidCheckpoint
		}
		result = VerifiedStatement{SourceType: StatementAccountKeyEnrollment, AccountID: fields[0], Fingerprint: fingerprint, Reason: "enroll"}
	case StatementAccountKeyRotation:
		if len(fields) != rotationStatementFieldCount {
			return result, ErrInvalidCheckpoint
		}
		rotatedAt, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return result, ErrInvalidCheckpoint
		}
		rotation := proto.KeyRotationStatement{
			AccountID: fields[0], OldFingerprint: fields[1], NewFingerprint: fields[2],
			RotatedAt: rotatedAt, Reason: fields[4], OldPublicKey: fields[5],
			NewPublicKey: fields[6], OldSignature: fields[7], NewSignature: fields[8],
		}
		reencoded, encodeErr := EncodeAccountKeyRotationStatement(rotation)
		if rotation.AccountID != expectedAccountID || encodeErr != nil || string(reencoded) != string(statement) || verifyRotation(rotation) != nil {
			return result, ErrInvalidCheckpoint
		}
		result = VerifiedStatement{SourceType: StatementAccountKeyRotation, AccountID: rotation.AccountID, Fingerprint: rotation.NewFingerprint, Reason: rotation.Reason}
	case StatementMLSLeafBinding:
		if len(fields) != mlsLeafStatementFieldCount {
			return result, ErrInvalidCheckpoint
		}
		notBefore, beforeErr := strconv.ParseInt(fields[4], 10, 64)
		notAfter, afterErr := strconv.ParseInt(fields[5], 10, 64)
		declaration := proto.MLSLeafDeclaration{
			AccountID: fields[0], DeviceID: fields[1], SignatureKey: fields[2],
			SignatureKeyFingerprint: fields[3], NotBefore: notBefore, NotAfter: notAfter,
			Reason: fields[6], Signature: fields[7],
		}
		reencoded, encodeErr := EncodeMLSLeafBindingStatement(declaration, fields[8])
		if beforeErr != nil || afterErr != nil || declaration.AccountID != expectedAccountID || encodeErr != nil || string(reencoded) != string(statement) || verifyLeafBinding(declaration, fields[8]) != nil {
			return result, ErrInvalidCheckpoint
		}
		result = VerifiedStatement{SourceType: StatementMLSLeafBinding, AccountID: declaration.AccountID, DeviceID: declaration.DeviceID, Fingerprint: declaration.SignatureKeyFingerprint, Reason: declaration.Reason}
	default:
		return result, ErrInvalidCheckpoint
	}
	digest := sha256.Sum256(statement)
	result.Digest = hex.EncodeToString(digest[:])
	return result, nil
}

func verifyRotation(statement proto.KeyRotationStatement) error {
	oldPEM, err := base64.StdEncoding.DecodeString(statement.OldPublicKey)
	if err != nil || crypto.AccountKeyFingerprint(oldPEM) != statement.OldFingerprint {
		return errors.New("invalid old account key")
	}
	newPEM, err := base64.StdEncoding.DecodeString(statement.NewPublicKey)
	if err != nil || crypto.AccountKeyFingerprint(newPEM) != statement.NewFingerprint {
		return errors.New("invalid new account key")
	}
	canonical := statement.Canonical()
	if err := verifyAccountSignature(string(oldPEM), statement.OldSignature, canonical); err != nil {
		return err
	}
	return verifyAccountSignature(string(newPEM), statement.NewSignature, canonical)
}

func verifyLeafBinding(declaration proto.MLSLeafDeclaration, accountPublicKey string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(declaration.SignatureKey)
	if err != nil {
		return err
	}
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(keyBytes)
	if err != nil || fingerprint != declaration.SignatureKeyFingerprint {
		return errors.New("invalid MLS leaf key")
	}
	return verifyAccountSignature(accountPublicKey, declaration.Signature, declaration.Canonical())
}

func verifyAccountSignature(publicKeyPEM, signatureB64, canonical string) error {
	publicKey, err := crypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	return crypto.VerifySignature(publicKey, canonical, signature)
}

func verifyAccountSignatureBytes(publicKeyPEM string, signature []byte, canonical string) error {
	publicKey, err := crypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	return crypto.VerifySignature(publicKey, canonical, signature)
}
