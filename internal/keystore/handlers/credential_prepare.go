package handlers

import (
	"encoding/base64"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleCredentialExecutionPrepare mints one execution nonce (see
// credential_nonces.go). The response is the nonce and its deadline, nothing
// else.
func HandleCredentialExecutionPrepare(d Deps, _ proto.CredentialExecutionPrepareRequest) proto.BaseResponse {
	raw := make([]byte, proto.CredentialExecutionNonceBytes)
	if err := d.FillRandom(raw); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "credential execution nonce generation failed")
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	deadline, err := d.CredentialNonces.Put(nonce, d.Now())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, err.Error())
	}
	return proto.BaseResponse{Success: true, Data: proto.CredentialExecutionPrepareResponseData{
		ExecutionNonce: nonce,
		ExpiresAt:      deadline.UTC().Format(time.RFC3339),
	}}
}
