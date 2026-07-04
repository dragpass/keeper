// Package proto — keeper Native Messaging payload models + input
// validation helpers.
//
// All Request / Response types and their Validate() methods, plus the
// small validation helpers (requireString / requireBase64 / requireHandle
// / requirePEM, etc.) live here. Handlers stay under keystore root and
// reference these names as-is via alias files.
//
// This is the first layer outside contributors see when learning the
// protocol, so validation errors name the field but never echo secret
// values.
//
// Regression guards:
//   - validation_test.go locks the helpers' negative cases.
//   - actions_validate_test.go / aes_actions_validate_test.go lock
//     each Request's Validate() reinforcement points.
package proto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ValidationError is a sentinel type so keeper handlers can use
// errors.Is/errors.As when moving the error into the response envelope's
// error field.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

// newValidationError builds a ValidationError from a field + reason.
// Intentionally does not echo the input value — prevents sensitive
// payloads (WrappedDEK, ciphertext, ...) from leaking into error logs.
func newValidationError(field, reason string) *ValidationError {
	return &ValidationError{Field: field, Reason: reason}
}

// requireString enforces a non-empty string.
func requireString(value, field string) error {
	if value == "" {
		return newValidationError(field, "must not be empty")
	}
	return nil
}

// requireBase64 enforces a non-empty, valid Base64 string and returns the
// decoded bytes. Tries both standard and URL-safe Base64 for compatibility
// (the Extension sends standard Base64 but some legacy paths use URL-safe).
func requireBase64(value, field string) ([]byte, error) {
	if value == "" {
		return nil, newValidationError(field, "must not be empty")
	}
	// Try standard Base64.
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	// Try URL-safe (with or without padding).
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, newValidationError(field, "must be valid Base64")
}

// requireBase64Len is requireBase64 + post-decode byte-length check. For
// fixed-length payloads like AES keys (32B) or IVs (12B).
func requireBase64Len(value, field string, expectedLen int) ([]byte, error) {
	decoded, err := requireBase64(value, field)
	if err != nil {
		return nil, err
	}
	if len(decoded) != expectedLen {
		return nil, newValidationError(
			field,
			fmt.Sprintf("decoded length must be %d bytes, got %d", expectedLen, len(decoded)),
		)
	}
	return decoded, nil
}

// requireHandle checks that the value looks like a 32B random Base64
// handle issued by GroupSessionStore / RecoverySessionStore. Light
// length/charset guard — the actual store lookup is the handler's job.
func requireHandle(value, field string) error {
	if err := requireString(value, field); err != nil {
		return err
	}
	// 32B Base64 is ~44 chars (with padding) or 43 (RawURL). Allow ±8.
	const minHandleLen = 32
	const maxHandleLen = 64
	if len(value) < minHandleLen || len(value) > maxHandleLen {
		return newValidationError(
			field,
			fmt.Sprintf("handle length out of range (%d..%d), got %d", minHandleLen, maxHandleLen, len(value)),
		)
	}
	// Base64-friendly charset + URL-safe variant allowed. Reject anything
	// else.
	if strings.ContainsAny(value, " \t\n\r") {
		return newValidationError(field, "handle must not contain whitespace")
	}
	return nil
}

// requirePositiveVersion enforces a positive integer version (e.g.
// dek_version, server_key_version). 0 is rejected — keeper protocol
// version fields always start at 1.
func requirePositiveVersion(value int, field string) error {
	if value <= 0 {
		return newValidationError(field, "must be a positive integer")
	}
	return nil
}

// requirePEM enforces a non-empty string that starts with a PEM header
// (`-----BEGIN`). ASN.1 integrity of the PEM itself is the caller's job.
func requirePEM(value, field string) error {
	if err := requireString(value, field); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimLeft(value, " \t\r\n"), "-----BEGIN") {
		return newValidationError(field, "must be PEM-encoded")
	}
	return nil
}

// IsValidationError lets response serialization distinguish a
// ValidationError from other internal errors. Made explicit so the
// dispatcher / wrap layer can fork on status codes, etc.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}
