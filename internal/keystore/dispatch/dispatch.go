// Package dispatch — Native Messaging request routing.
//
// dispatcher / messaging / utils are split out of the keystore root into the
// dispatch subpackage. App.HandleRequest is a thin wrapper that delegates to
// dispatch.HandleRequest.
//
// dispatch does not import the keystore root (avoids an import cycle). The
// caller (App) injects logger.Logger and handlers.Deps explicitly — same Deps
// pattern used elsewhere.
//
// This file holds only the request routing entry points. The action→handler
// registry is assembled from per-domain fragments in registry.go and the
// registry_*.go files.
package dispatch

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleRequest parses an incoming msg, looks up the action, and invokes the
// handler. The request's RequestID is echoed back in the response so the
// Extension can multiplex; if JSON parsing fails and RequestID cannot be
// read, an empty string is sent.
//
// The caller (App) injects log and deps explicitly so the keystore root is
// not imported, avoiding an import cycle.
func HandleRequest(log logger.Logger, deps handlers.Deps, msg []byte) proto.BaseResponse {
	var base proto.BaseRequest
	if err := json.Unmarshal(msg, &base); err != nil {
		log.Printf("failed to unmarshal base request: %v", err)
		return proto.BaseResponse{Success: false, Error: "invalid JSON format"}
	}

	log.Printf("received action: %s request_id: %s", base.Action, base.RequestID)

	resp := dispatchAction(log, deps, base)
	resp.RequestID = base.RequestID
	return resp
}

// dispatchAction looks up the handler in actionRegistry and forwards deps +
// payload. Unknown actions are logged and respond with the unsupported code.
func dispatchAction(log logger.Logger, deps handlers.Deps, base proto.BaseRequest) proto.BaseResponse {
	handler, ok := actionRegistry[base.Action]
	if !ok {
		log.Printf("unknown action: %s", base.Action)
		return errs.CodeResponse(errs.ErrCodeUnsupported, "unknown action: "+base.Action)
	}
	return handler(deps, base.Payload)
}
