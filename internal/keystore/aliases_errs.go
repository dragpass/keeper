// Keep the error alias used by root-package tests.

package keystore

import "github.com/dragpass/keeper/internal/keystore/errs"

const (
	ErrCodeUnsupported = errs.ErrCodeUnsupported

	// String-typed for BaseResponse.ErrorCode; localrpc builds a busy refusal.
	ErrCodeChatRuntimeBusy          = string(errs.ErrCodeChatRuntimeBusy)
	ErrCodeChatRuntimeLeaseRequired = string(errs.ErrCodeChatRuntimeLeaseRequired)
	ErrCodeChatRuntimeRevoked       = string(errs.ErrCodeChatRuntimeRevoked)
)
