package dispatch

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// process is catch the pattern of unmarshaling, validating, and handling requests
// [Unmarshal] -> [Validate]-> [Handler call] pattern
//
// The Validator interface lives in the proto/ package (proto.Validator). The
// dispatcher uses this helper to pass the decoded request object to the typed
// handler.
func process[T any](payload json.RawMessage, handler func(T) proto.BaseResponse) proto.BaseResponse {
	var req T

	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation, "invalid payload format")
		}
	}

	if v, ok := any(&req).(proto.Validator); ok {
		if err := v.Validate(); err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
		}
	}

	return handler(req)
}
