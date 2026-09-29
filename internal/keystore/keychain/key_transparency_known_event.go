package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/dragpass/keeper/config"
)

const knownKeyTransparencyEventVersion = 1

type knownKeyTransparencyEvent struct {
	Version         int    `json:"v"`
	AccountID       string `json:"account_id"`
	StatementSHA256 string `json:"statement_sha256"`
}

type pendingKeyTransparencyEvent struct {
	Version         int    `json:"v"`
	AccountID       string `json:"account_id"`
	StatementSHA256 string `json:"statement_sha256"`
}

func PendingKeyTransparencyEventID(material []byte) (string, error) {
	if len(material) == 0 || len(material) > 64*1024 {
		return "", errors.New("key transparency event pending identity is invalid")
	}
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:]), nil
}

func keyTransparencyEventDigest(accountID string, statement []byte) ([32]byte, error) {
	var zero [32]byte
	if !isCanonicalKeyTransparencyAccountID(accountID) || len(statement) == 0 || len(statement) > 64*1024 {
		return zero, errors.New("key transparency event identity or statement is invalid")
	}
	input := make([]byte, 0, len(accountID)+1+len(statement))
	input = append(input, accountID...)
	input = append(input, 0)
	input = append(input, statement...)
	return sha256.Sum256(input), nil
}

func knownKeyTransparencyEventAccount(accountID string, digest [32]byte) string {
	return config.KeyTransparencyKnownEventPrefix + accountID + ":" + hex.EncodeToString(digest[:])
}

func saveKnownKeyTransparencyEventDigest(store SecretStore, accountID string, digest [32]byte) error {
	record := knownKeyTransparencyEvent{
		Version:         knownKeyTransparencyEventVersion,
		AccountID:       accountID,
		StatementSHA256: hex.EncodeToString(digest[:]),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return store.Set(config.Service, knownKeyTransparencyEventAccount(accountID, digest), string(encoded))
}

func StageKeyTransparencyEvent(store SecretStore, accountID, pendingID string, statement []byte) error {
	digest, err := keyTransparencyEventDigest(accountID, statement)
	if err != nil || !isSHA256Hex(pendingID) {
		return errors.New("key transparency event identity or pending id is invalid")
	}
	record := pendingKeyTransparencyEvent{
		Version:         knownKeyTransparencyEventVersion,
		AccountID:       accountID,
		StatementSHA256: hex.EncodeToString(digest[:]),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	key := config.KeyTransparencyPendingEventPrefix + pendingID
	if current, getErr := store.Get(config.Service, key); getErr == nil {
		if current != string(encoded) {
			return errors.New("a different key transparency event is already pending")
		}
		return nil
	} else if !errors.Is(getErr, ErrSecretNotFound) {
		return getErr
	}
	return store.Set(config.Service, key, string(encoded))
}

func PromoteKeyTransparencyEvent(store SecretStore, pendingID string) error {
	if !isSHA256Hex(pendingID) {
		return errors.New("key transparency event pending id is invalid")
	}
	key := config.KeyTransparencyPendingEventPrefix + pendingID
	raw, err := store.Get(config.Service, key)
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var record pendingKeyTransparencyEvent
	if err := decodeStrictJSON(raw, &record); err != nil || record.Version != knownKeyTransparencyEventVersion ||
		!isCanonicalKeyTransparencyAccountID(record.AccountID) || !isSHA256Hex(record.StatementSHA256) {
		return errors.New("pending key transparency event record is malformed")
	}
	statementDigest, err := hex.DecodeString(record.StatementSHA256)
	if err != nil || len(statementDigest) != sha256.Size {
		return errors.New("pending key transparency event digest is malformed")
	}
	var digest [32]byte
	copy(digest[:], statementDigest)
	if err := saveKnownKeyTransparencyEventDigest(store, record.AccountID, digest); err != nil {
		return err
	}
	if err := store.Delete(config.Service, key); err != nil && !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	return nil
}

func DeletePendingKeyTransparencyEvent(store SecretStore, pendingID string) error {
	if !isSHA256Hex(pendingID) {
		return errors.New("key transparency event pending id is invalid")
	}
	err := store.Delete(config.Service, config.KeyTransparencyPendingEventPrefix+pendingID)
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	return err
}

func HasKnownKeyTransparencyEvent(store SecretStore, accountID string, statement []byte) (bool, error) {
	digest, err := keyTransparencyEventDigest(accountID, statement)
	if err != nil {
		return false, err
	}
	raw, err := store.Get(config.Service, knownKeyTransparencyEventAccount(accountID, digest))
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	var record knownKeyTransparencyEvent
	if err := decodeStrictJSON(raw, &record); err != nil {
		return false, errors.New("known key transparency event record is malformed")
	}
	if record.Version != knownKeyTransparencyEventVersion || record.AccountID != accountID || record.StatementSHA256 != hex.EncodeToString(digest[:]) {
		return false, errors.New("known key transparency event record does not match its key")
	}
	return true, nil
}

func decodeStrictJSON(raw string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("record contains trailing data")
	}
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func isCanonicalKeyTransparencyAccountID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" ||
		value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}
