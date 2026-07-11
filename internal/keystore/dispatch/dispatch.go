// Package dispatch — Native Messaging request routing.
//
// dispatcher / messaging / utils are split out of the keystore root into the
// dispatch subpackage. App.HandleRequest is a thin wrapper that delegates to
// dispatch.HandleRequest.
//
// dispatch does not import the keystore root (avoids an import cycle). The
// caller (App) injects logger.Logger and handlers.Deps explicitly — same Deps
// pattern used elsewhere.
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

// actionHandlerFunc is the unified signature for the dispatcher action map
// ("action registry" — Go pattern terminology, unrelated to the DragPass
// product DragLink inventory).
type actionHandlerFunc func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse

// wrap adapts a typed handler (func(handlers.Deps, T) proto.BaseResponse) to
// actionHandlerFunc. process[T] handles JSON decoding and the Validate call,
// so wrap is a simple delegation.
func wrap[T any](handler func(handlers.Deps, T) proto.BaseResponse) actionHandlerFunc {
	return func(d handlers.Deps, payload json.RawMessage) proto.BaseResponse {
		return process(payload, func(req T) proto.BaseResponse {
			return handler(d, req)
		})
	}
}

// actionRegistry maps action strings to handler functions.
// Add a new action with a single line. The registration order matches the
// group order in proto/actions.go.
var actionRegistry = map[string]actionHandlerFunc{
	proto.ActionPing:            wrap(handlers.HandlePing),
	proto.ActionGenerateKeypair: wrap(handlers.HandleGenerateKeypair),

	proto.ActionGetDeviceKey:    wrap(handlers.HandleGetDeviceKey),
	proto.ActionSaveDeviceKey:   wrap(handlers.HandleSaveDeviceKey),
	proto.ActionDeleteDeviceKey: wrap(handlers.HandleDeleteDeviceKey),

	// local self-recovery: wipe this device's account-scoped key material
	proto.ActionResetDeviceIdentity: wrap(handlers.HandleResetDeviceIdentity),

	proto.ActionSaveSessionCode: wrap(handlers.HandleSaveSessionCode),
	proto.ActionGetSessionCode:  wrap(handlers.HandleGetSessionCode),

	proto.ActionGetPublicKey:       wrap(handlers.HandleGetPublicKey),
	proto.ActionGetServerPublicKey: wrap(handlers.HandleGetServerPublicKey),

	// multi-version server public key refresh
	proto.ActionRefreshServerKeys: wrap(handlers.HandleRefreshServerKeys),

	// voluntary user RSA keypair rotation (two-step)
	proto.ActionRotateUserKeypairPrepare: wrap(handlers.HandleRotateUserKeypairPrepare),
	proto.ActionRotateUserKeypairPromote: wrap(handlers.HandleRotateUserKeypairPromote),

	// user keypair rotation partial-failure recovery (status/abort)
	proto.ActionRotateUserKeypairStatus: wrap(handlers.HandleRotateUserKeypairStatus),
	proto.ActionRotateUserKeypairAbort:  wrap(handlers.HandleRotateUserKeypairAbort),

	// voluntary DeviceKey rotation (single composite action)
	proto.ActionRotateDeviceKey: wrap(handlers.HandleRotateDeviceKey),

	proto.ActionSignAlias:              wrap(handlers.HandleSignAlias),
	proto.ActionSignAliasWithTimestamp: wrap(handlers.HandleSignAliasWithTimestamp),
	proto.ActionSignChallengeToken:     wrap(handlers.HandleSignChallengeToken),

	proto.ActionRecoverySign:                    wrap(handlers.HandleRecoverySign),
	proto.ActionGenerateKeypairWithRecoveryWrap: wrap(handlers.HandleGenerateKeypairWithRecoveryWrap),
	// Re-wrap the active privkey when a new RK24 is issued (the keypair
	// itself is unchanged).
	proto.ActionWrapActivePrivateKey: wrap(handlers.HandleWrapActivePrivateKey),

	proto.ActionRecoverySessionOpen:  wrap(handlers.HandleRecoverySessionOpen),
	proto.ActionRecoverySessionClose: wrap(handlers.HandleRecoverySessionClose),

	proto.ActionWrapGroupDEK:   wrap(handlers.HandleWrapGroupDEK),
	proto.ActionUnwrapGroupDEK: wrap(handlers.HandleUnwrapGroupDEK),

	proto.ActionDEKRewrapWithOldKey: wrap(handlers.HandleDEKRewrapWithOldKey),

	// Group DEK opaque handle
	proto.ActionGroupSessionOpen:        wrap(handlers.HandleGroupSessionOpen),
	proto.ActionGroupSessionOpenWithRaw: wrap(handlers.HandleGroupSessionOpenWithRaw),
	proto.ActionGroupSessionClose:       wrap(handlers.HandleGroupSessionClose),
	proto.ActionGroupSessionStatus:      wrap(handlers.HandleGroupSessionStatus),

	// Admin-path raw-free composite actions (Group DEK never crosses into JS).
	proto.ActionGroupDEKGenerateAndOpen: wrap(handlers.HandleGroupDEKGenerateAndOpen),
	proto.ActionDEKRewrapForMember:      wrap(handlers.HandleDEKRewrapForMember),

	// Item DEK / personal DEK delegated to Keeper.
	// The old ActionAESUnwrapAndDecrypt / ActionDEKUnwrapAndDecrypt
	// (returning plaintext) were removed in the plaintext-removal follow-up
	// §A and replaced by *_to_clipboard / *_meta variants.
	proto.ActionAESGenerateAndWrap:      wrap(handlers.HandleAESGenerateAndWrap),
	proto.ActionAESUnwrapAndEncrypt:     wrap(handlers.HandleAESUnwrapAndEncrypt),
	proto.ActionAESUnshareRewrapMeta:    wrap(handlers.HandleAESUnshareRewrapMeta),
	proto.ActionAESUnwrapAndDecryptMeta: wrap(handlers.HandleAESUnwrapAndDecryptMeta),

	proto.ActionDEKGenerateAndWrapPassword: wrap(handlers.HandleDEKGenerateAndWrapPassword),
	proto.ActionDEKGenerateAndWrapDual:     wrap(handlers.HandleDEKGenerateAndWrapDual),
	proto.ActionDEKRotateToDeviceKey:       wrap(handlers.HandleDEKRotateToDeviceKey),
	// Re-wrap DEK under a new password (deviceMaster / DEK itself unchanged).
	proto.ActionDEKRotateToNewPassword:  wrap(handlers.HandleDEKRotateToNewPassword),
	proto.ActionDEKUnwrapAndEncrypt:     wrap(handlers.HandleDEKUnwrapAndEncrypt),
	proto.ActionDEKUnwrapAndDecryptMeta: wrap(handlers.HandleDEKUnwrapAndDecryptMeta),

	// decrypt-to-clipboard (Keeper-owned plaintext sink)
	proto.ActionAESUnwrapAndDecryptToClipboard: wrap(handlers.HandleAESUnwrapAndDecryptToClipboard),
	proto.ActionDEKUnwrapAndDecryptToClipboard: wrap(handlers.HandleDEKUnwrapAndDecryptToClipboard),
	proto.ActionGroupDecryptToClipboard:        wrap(handlers.HandleGroupDecryptToClipboard),

	// org token → external guest share re-encryption (Keeper-owned re-encrypt
	// sink; plaintext / Group DEK never enter the JS heap).
	proto.ActionGroupTranscryptForGuest: wrap(handlers.HandleGroupTranscryptForGuest),

	// per-device request-signing key actions
	proto.ActionRequestKeyGenerate: wrap(handlers.HandleRequestKeyGenerate),
	proto.ActionRequestKeyStatus:   wrap(handlers.HandleRequestKeyStatus),
	proto.ActionSignRequest:        wrap(handlers.HandleSignRequest),
	// request-signing key rotation
	proto.ActionRotateRequestKeyPrepare: wrap(handlers.HandleRotateRequestKeyPrepare),
	proto.ActionRotateRequestKeyPromote: wrap(handlers.HandleRotateRequestKeyPromote),
	proto.ActionRotateRequestKeyAbort:   wrap(handlers.HandleRotateRequestKeyAbort),

	// test-only — query SHA-256 hash recorded in MemoryClipboard under
	// KEEPER_E2E_MODE.
	proto.ActionClipboardGetLastHash: wrap(handlers.HandleClipboardGetLastHash),
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
