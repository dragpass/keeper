// envelope_models.go — Shared request/response envelopes + empty payload
// structs. BaseRequest / BaseResponse + 8 empty payloads (PingRequest,
// GetDeviceKeyRequest, DeleteDeviceKeyRequest, GetSessionCodeRequest,
// GetPublicKeyRequest, GetServerPublicKeyRequest,
// SaveDeviceKeyResponseData, DeleteDeviceKeyResponseData).

package proto

import (
	"encoding/json"
)

// BaseRequest is the common envelope for requests the Extension sends
// over Native Messaging. RequestID is a UUID minted by the Extension's
// sendNativeMessage per request, which the Keeper echoes verbatim in
// BaseResponse.RequestID. The Extension uses it to match responses for
// concurrent multi-request flows. Older Extension versions may omit it;
// in that case the response RequestID is also the empty string (the
// Extension falls back to FIFO).
type BaseRequest struct {
	Action    string          `json:"action"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type PingRequest struct{}
type GetDeviceKeyRequest struct{}
type DeleteDeviceKeyRequest struct{}
type GetSessionCodeRequest struct{}
type GetPublicKeyRequest struct{}
type GetServerPublicKeyRequest struct{}
type SaveDeviceKeyResponseData struct{}
type DeleteDeviceKeyResponseData struct{}

// BaseResponse is the response envelope corresponding to BaseRequest.
// RequestID echoes the same value as the request. When the request ID
// can't be read (e.g. JSON parse failure) it goes out as the empty
// string; the Extension matches empty-request_id responses to the
// pending-queue FIFO (backwards compatibility).
//
// ErrorCode (P2 Error Taxonomy): on failure, optionally carries a
// coarse-grained category token. An empty string is excluded from
// serialization (omitempty) so older Extensions ignore it and keep
// working as before. See ErrorCode constants in errors.go for the
// defined values.
type BaseResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Data      any    `json:"data,omitempty"`
}
