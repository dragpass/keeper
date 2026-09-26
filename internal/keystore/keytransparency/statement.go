package keytransparency

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	StatementAccountKeyRotation = "account_key_rotation"
	StatementMLSLeafBinding     = "mls_leaf_binding"
	statementDomain             = "dragpass.kt.statement"
	statementMaxBytes           = 64 * 1024
)

func EncodeStatement(kind string, fields ...[]byte) ([]byte, error) {
	if kind != StatementAccountKeyRotation && kind != StatementMLSLeafBinding {
		return nil, errors.New("unknown key transparency statement kind")
	}
	if len(fields) == 0 || len(fields) > 16 {
		return nil, errors.New("invalid key transparency statement field count")
	}
	parts := []string{statementDomain, "1", kind}
	for _, field := range fields {
		if len(field) == 0 || len(field) > statementMaxBytes {
			return nil, errors.New("invalid key transparency statement field size")
		}
		parts = append(parts, base64.RawURLEncoding.EncodeToString(field))
	}
	statement := []byte(strings.Join(parts, "|"))
	if len(statement) > statementMaxBytes {
		return nil, errors.New("key transparency statement is too large")
	}
	return statement, nil
}

func EncodeAccountKeyRotationStatement(statement proto.KeyRotationStatement) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	return EncodeStatement(StatementAccountKeyRotation,
		[]byte(statement.AccountID), []byte(statement.OldFingerprint), []byte(statement.NewFingerprint),
		[]byte(strconv.FormatInt(statement.RotatedAt, 10)), []byte(statement.Reason),
		[]byte(statement.OldPublicKey), []byte(statement.NewPublicKey),
		[]byte(statement.OldSignature), []byte(statement.NewSignature),
	)
}

func EncodeMLSLeafBindingStatement(declaration proto.MLSLeafDeclaration, accountPublicKey string) ([]byte, error) {
	if err := declaration.Validate(); err != nil {
		return nil, err
	}
	if len(accountPublicKey) == 0 || len(accountPublicKey) > 64*1024 {
		return nil, errors.New("account public key has an invalid size")
	}
	return EncodeStatement(StatementMLSLeafBinding,
		[]byte(declaration.AccountID), []byte(declaration.DeviceID), []byte(declaration.SignatureKey),
		[]byte(declaration.SignatureKeyFingerprint), []byte(strconv.FormatInt(declaration.NotBefore, 10)),
		[]byte(strconv.FormatInt(declaration.NotAfter, 10)), []byte(declaration.Reason),
		[]byte(declaration.Signature), []byte(accountPublicKey),
	)
}
