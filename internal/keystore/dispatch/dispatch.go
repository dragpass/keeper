// Package dispatch — Native Messaging request routing.
//
// dispatcher / messaging / utils are split out of the keystore root into the
// dispatch subpackage. App.HandleRequest is a thin wrapper that delegates to
// dispatch.HandleRequestGated.
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
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// Gate may refuse an action before its handler runs. It sees the action the
// dispatcher is about to run, parsed once, so the two cannot disagree.
type Gate func(action string) (refusal proto.BaseResponse, admitted bool)

// HandleRequestGated parses an incoming msg, looks up the action, and invokes
// the handler. The request's RequestID is echoed back in the response so the
// Extension can multiplex; if JSON parsing fails and RequestID cannot be read,
// an empty string is sent.
//
// gate, when not nil, is consulted after the parse and before the handler. A
// refusal runs nothing and still echoes the RequestID.
//
// The caller (App) injects log and deps explicitly so the keystore root is
// not imported, avoiding an import cycle.
func HandleRequestGated(log logger.Logger, deps handlers.Deps, msg []byte, gate Gate) proto.BaseResponse {
	var base proto.BaseRequest
	if err := json.Unmarshal(msg, &base); err != nil {
		log.Printf("failed to unmarshal base request: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid JSON format")
	}

	log.Printf("received action: %s request_id: %s", base.Action, base.RequestID)

	// The payload carries passwords, recovery keys and plaintext; handlers
	// decode their own copies and wipe what they can. Best effort: Go strings
	// decoded from it are not covered.
	defer secure.Zeroize(base.Payload)

	var resp proto.BaseResponse
	if refusal, admitted := admit(gate, base.Action); !admitted {
		log.Printf("action refused before dispatch: %s", base.Action)
		resp = refusal
	} else {
		resp = dispatchAction(log, deps, base)
	}
	resp.RequestID = base.RequestID
	return resp
}

func admit(gate Gate, action string) (proto.BaseResponse, bool) {
	if gate == nil {
		return proto.BaseResponse{}, true
	}
	return gate(action)
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
