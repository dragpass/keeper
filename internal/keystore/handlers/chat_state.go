// chat_state.go — the five conversation-state actions of DragPass chat v2.
//
// None of these encrypts anything. They decide, durably and under a
// per-conversation lock, which chain position a sender may use next and which
// ciphertext a retransmission must reuse. Storage and its guarantees live in
// internal/keystore/chatstate; this file is the protocol edge.
//
// The order every permit-gated action runs, before the state directory is
// touched at all:
//
//	size cap → strict decode (no unknown / duplicate / missing field)
//	  → structural validation
//	  → the request and the permit name the same conversation
//	  → the permit window holds (issued_at <= now+5, now < expires_at,
//	    expires_at - issued_at == 300)
//	  → the server signature verifies under the named key version (unknown
//	    version fails closed, no active-key fallback)
//	  → only now is a store opened
//
// The last line is the point and is tested as such: a caller without a permit
// does not merely get an error, it leaves no trace in the state directory,
// because nothing opened it.
//
// The owner account is taken from the permit, never from the request. The state
// directory is partitioned by owner, so letting a caller name its own owner
// would let it pick which account's chain it advances.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// chatStatePermitClockSkewSeconds — how far into the future a permit's
// issued_at may sit. Ordinary server/client drift and nothing more, the same
// allowance the chat read permit gets.
const chatStatePermitClockSkewSeconds = 5

// HandleChatStateReserveSend consumes chain positions and returns them only
// after the consumption is fsynced.
func HandleChatStateReserveSend(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStateReserveSendRequest
	store, watermark, resp, ok := openChatState(d, payload, &req)
	if !ok {
		return resp
	}
	defer store.Close()

	reservation, err := store.Reserve(req.ConversationID, req.Count, watermark)
	if err != nil {
		return chatStateFailure(d, "reserve", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatStateReserveSendResponseData{
		Epoch:           reservation.Epoch,
		FirstChainIndex: reservation.FirstChainIndex,
		Count:           reservation.Count,
		Generation:      reservation.Generation,
	}}
}

// HandleChatStateCommitOutbox stores the ciphertext built for a reserved
// position, or returns the one already stored under the same client message id.
func HandleChatStateCommitOutbox(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStateCommitOutboxRequest
	store, watermark, resp, ok := openChatState(d, payload, &req)
	if !ok {
		return resp
	}
	defer store.Close()

	iv, ciphertext, decodeErr := decodeSealedPair(req.IVB64, req.CiphertextB64)
	if decodeErr != nil {
		return chatStateInvalidInput(decodeErr.Error())
	}
	stored, created, err := store.CommitOutbox(req.ConversationID, watermark, chatstate.OutboxEntry{
		ClientMessageID: req.ClientMessageID,
		Position:        chatstate.Position{Epoch: req.Epoch, ChainIndex: req.ChainIndex},
		IV:              iv,
		Ciphertext:      ciphertext,
	})
	if err != nil {
		return chatStateFailure(d, "commit outbox", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatStateCommitOutboxResponseData{
		Stored:        created,
		Epoch:         stored.Position.Epoch,
		ChainIndex:    stored.Position.ChainIndex,
		IVB64:         base64.StdEncoding.EncodeToString(stored.IV),
		CiphertextB64: base64.StdEncoding.EncodeToString(stored.Ciphertext),
	}}
}

// HandleChatStateReadOutbox returns the bytes a retransmission must send.
func HandleChatStateReadOutbox(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStateReadOutboxRequest
	store, watermark, resp, ok := openChatState(d, payload, &req)
	if !ok {
		return resp
	}
	defer store.Close()

	entry, err := store.ReadOutbox(req.ConversationID, watermark, req.ClientMessageID)
	if err != nil {
		return chatStateFailure(d, "read outbox", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatStateReadOutboxResponseData{
		Epoch:         entry.Position.Epoch,
		ChainIndex:    entry.Position.ChainIndex,
		IVB64:         base64.StdEncoding.EncodeToString(entry.IV),
		CiphertextB64: base64.StdEncoding.EncodeToString(entry.Ciphertext),
	}}
}

// HandleChatStateMarkReceived records an inbound position idempotently.
func HandleChatStateMarkReceived(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStateMarkReceivedRequest
	store, watermark, resp, ok := openChatState(d, payload, &req)
	if !ok {
		return resp
	}
	defer store.Close()

	first, generation, err := store.MarkReceived(
		req.ConversationID, watermark,
		chatstate.Position{Epoch: req.Epoch, ChainIndex: req.ChainIndex},
	)
	if err != nil {
		return chatStateFailure(d, "mark received", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatStateMarkReceivedResponseData{
		FirstDelivery: first,
		Generation:    generation,
	}}
}

// HandleChatStatePurge erases one account's chat state. The only one of the
// five with no permit; see actions_chat_state.go for why a deletion this local
// is not worth a server round trip.
func HandleChatStatePurge(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStatePurgeRequest
	if resp, ok := decodeChatStateRequest(payload, &req); !ok {
		return resp
	}
	removed, err := chatstate.Purge(d.Store, req.OwnerAccountID)
	if err != nil {
		return chatStateFailure(d, "purge", err)
	}
	d.Logger.Printf("chat state purged for %d conversations", removed)
	return proto.BaseResponse{Success: true, Data: proto.ChatStatePurgeResponseData{
		RemovedConversations: removed,
	}}
}

// ────────────────────────────────────────────────────────────────────────
// Authorization and decoding.
// ────────────────────────────────────────────────────────────────────────

// openChatState runs the whole gate and opens the owner's store. It returns a
// store only when every check passed, so no caller can reach the filesystem by
// forgetting one.
func openChatState(
	d Deps, payload json.RawMessage, req proto.ChatStateBound,
) (*chatstate.Store, chatstate.ServerWatermark, proto.BaseResponse, bool) {
	if resp, ok := decodeChatStateRequest(payload, req); !ok {
		return nil, chatstate.ServerWatermark{}, resp, false
	}
	permit, orgID, conversationID := req.ChatStateContext()
	if permit.OrgID != orgID || permit.ConversationID != conversationID {
		return nil, chatstate.ServerWatermark{}, chatStateNotAuthorized(d, "binding"), false
	}
	if !chatStatePermitWindowHolds(permit, d.Now().Unix()) {
		return nil, chatstate.ServerWatermark{}, chatStateNotAuthorized(d, "permit window"), false
	}
	if err := d.ServerKeyVerifier.Verify(
		proto.ChatStatePermitCanonical(permit), permit.Signature, permit.ServerKeyVersion,
	); err != nil {
		// The verifier's message names the failing step and sometimes the key
		// version; neither belongs in a reply to a caller that just failed to
		// prove authorization.
		return nil, chatstate.ServerWatermark{}, chatStateNotAuthorized(d, "signature"), false
	}

	store, err := chatstate.Open(d.Store, permit.AccountID)
	if err != nil {
		return nil, chatstate.ServerWatermark{}, chatStateFailure(d, "open", err), false
	}
	watermark := chatstate.ServerWatermark{
		Epoch:     permit.WatermarkEpoch,
		NextIndex: permit.WatermarkNextIndex,
	}
	return store, watermark, proto.BaseResponse{}, true
}

// decodeChatStateRequest applies the size cap, the strict decode, and the
// request's own Validate. These requests are bound into a server signature, so
// they decode through strictDecodeJSON rather than the dispatcher's shared
// json.Unmarshal: a duplicate `conversation_id` would otherwise verify against
// one value and advance the chain of another.
func decodeChatStateRequest(payload json.RawMessage, req proto.Validator) (proto.BaseResponse, bool) {
	if len(payload) > proto.ChatStateMaxRequestBytes {
		return chatStateInvalidInput("request exceeds the maximum size"), false
	}
	if err := strictDecodeJSON(payload, req); err != nil {
		return chatStateInvalidInput("invalid chat state request: " + err.Error()), false
	}
	if err := req.Validate(); err != nil {
		return chatStateInvalidInput(err.Error()), false
	}
	return proto.BaseResponse{}, true
}

// chatStatePermitWindowHolds checks the three timing rules the server promises
// to sign into every permit. The fixed span is checked, not assumed.
func chatStatePermitWindowHolds(p proto.ChatStatePermit, nowUnix int64) bool {
	if p.IssuedAt > nowUnix+chatStatePermitClockSkewSeconds {
		return false
	}
	if nowUnix >= p.ExpiresAt {
		return false
	}
	return p.ExpiresAt-p.IssuedAt == proto.ChatStatePermitTTLSeconds
}

func decodeSealedPair(ivB64, ciphertextB64 string) ([]byte, []byte, error) {
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, nil, errors.New("iv_b64 must be valid standard Base64")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, nil, errors.New("ciphertext_b64 must be valid standard Base64")
	}
	return iv, ciphertext, nil
}

// ────────────────────────────────────────────────────────────────────────
// Failure responses. Fixed strings: no store paths, no request payload, and no
// hint about which authorization check refused.
// ────────────────────────────────────────────────────────────────────────

func chatStateInvalidInput(message string) proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(proto.ChatStateErrorCodeInvalidInput), message)
}

func chatStateNotAuthorized(d Deps, stage string) proto.BaseResponse {
	d.Logger.Printf("chat state not authorized (%s check)", stage)
	return errs.CodeResponse(
		errs.ErrorCode(proto.ChatStateErrorCodeNotAuthorized),
		"chat state permit is not authorized",
	)
}

func chatStateFailure(d Deps, stage string, err error) proto.BaseResponse {
	code, message := proto.ChatStateErrorCodeStorageFailure, "chat state could not be read or written"
	switch {
	case errors.Is(err, chatstate.ErrRekeyRequired):
		code, message = proto.ChatStateErrorCodeRekeyRequired,
			"chat state is behind its anchor; the conversation needs a new epoch"
	case errors.Is(err, chatstate.ErrLockTimeout):
		code, message = proto.ChatStateErrorCodeLockTimeout,
			"another process is holding this conversation"
	case errors.Is(err, chatstate.ErrConflict):
		code, message = proto.ChatStateErrorCodeConflict, "chat state changed under the lock"
	case errors.Is(err, chatstate.ErrPositionTaken):
		code, message = proto.ChatStateErrorCodeConflict,
			"that chain position already carries a message"
	case errors.Is(err, chatstate.ErrPositionNotReserved):
		code, message = proto.ChatStateErrorCodeConflict, "that chain position was not reserved"
	case errors.Is(err, chatstate.ErrNotFound):
		code, message = proto.ChatStateErrorCodeNotFound, "no stored message for that client message id"
	}
	d.Logger.Printf("chat state %s failed: %s", stage, code)
	return errs.CodeResponse(errs.ErrorCode(code), message)
}
