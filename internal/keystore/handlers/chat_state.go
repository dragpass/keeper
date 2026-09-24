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
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// chatStatePermitClockSkewSeconds — how far into the future a permit's
// issued_at may sit. Ordinary server/client drift and nothing more.
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
		Position:        chatstate.Position{Epoch: req.Epoch, Generation: req.ChainIndex},
		IV:              iv,
		Ciphertext:      ciphertext,
	})
	if err != nil {
		return chatStateFailure(d, "commit outbox", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.ChatStateCommitOutboxResponseData{
		Stored:        created,
		Epoch:         stored.Position.Epoch,
		ChainIndex:    stored.Position.Generation,
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
		ChainIndex:    entry.Position.Generation,
		IVB64:         base64.StdEncoding.EncodeToString(entry.IV),
		CiphertextB64: base64.StdEncoding.EncodeToString(entry.Ciphertext),
		LeafIndex:     entry.Position.SenderLeafIndex,
		ContentType:   string(entry.Position.ContentType),
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
		chatstate.Position{
			Epoch:           req.Epoch,
			SenderLeafIndex: req.SenderLeafIndex,
			ContentType:     chatstate.ContentType(req.ContentType),
			Generation:      req.Generation,
		},
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
	if resp, ok := authorizeChatState(d, payload, req); !ok {
		return nil, chatstate.ServerWatermark{}, resp, false
	}
	permit, _, _ := req.ChatStateContext()
	return openChatStateStore(d, permit)
}

// openChatStateStore is openChatState after the gate: it opens the permit
// owner's store and carries the permit's watermark to it. Whether that
// watermark describes this device's chain at all is the store's to judge
// (chatstate.Record.ownsChain), because only the record knows this device's
// leaf and the epoch it entered at. Only a caller that has already run
// authorizeChatState may reach it.
func openChatStateStore(
	d Deps, permit proto.ChatStatePermit,
) (*chatstate.Store, chatstate.ServerWatermark, proto.BaseResponse, bool) {
	store, err := chatstate.Open(d.Store, permit.AccountID)
	if err != nil {
		return nil, chatstate.ServerWatermark{}, chatStateFailure(d, "open", err), false
	}
	watermark := chatstate.ServerWatermark{
		Epoch:                permit.WatermarkEpoch,
		LeafIndex:            permit.WatermarkLeafIndex,
		NextHandshakeIndex:   permit.WatermarkNextHandshake,
		NextApplicationIndex: permit.WatermarkNextApplication,
		PendingRemovals:      permit.PendingRemovalAccountIDs,

		PendingLeafReplacements: leafReplacementsOf(permit.PendingLeafReplacements),
	}
	return store, watermark, proto.BaseResponse{}, true
}

func leafReplacementsOf(entries []proto.ChatStateLeafReplacement) []chatstate.LeafReplacement {
	if len(entries) == 0 {
		return nil
	}
	out := make([]chatstate.LeafReplacement, len(entries))
	for i, e := range entries {
		out[i] = chatstate.LeafReplacement{AccountID: e.AccountID, NewFingerprint: e.NewSignatureKeyFP}
	}
	return out
}

// authorizeChatState is the permit gate without the store: decode, binding,
// window, signature. openChatState runs it first; an action that is gated by
// the same permit but reads no conversation state runs only this.
func authorizeChatState(d Deps, payload json.RawMessage, req proto.ChatStateBound) (proto.BaseResponse, bool) {
	return authorizeChatStateCapped(d, payload, req, proto.ChatStateMaxRequestBytes)
}

// authorizeChatStateCapped is authorizeChatState with the request's own size
// cap. The MLS actions carry KeyPackages, Commits, Welcomes and batches that
// one ciphertext's 32 KiB does not fit; everything after the cap is the same
// gate in the same order.
func authorizeChatStateCapped(
	d Deps, payload json.RawMessage, req proto.ChatStateBound, maxBytes int,
) (proto.BaseResponse, bool) {
	if resp, ok := decodeChatStateRequestCapped(payload, req, maxBytes); !ok {
		return resp, false
	}
	permit, orgID, conversationID := req.ChatStateContext()
	if permit.OrgID != orgID || permit.ConversationID != conversationID {
		return chatStateNotAuthorized(d, "binding"), false
	}
	if !chatStatePermitWindowHolds(permit, d.Now().Unix()) {
		return chatStateNotAuthorized(d, "permit window"), false
	}
	if err := d.ServerKeyVerifier.Verify(
		proto.ChatStatePermitCanonical(permit), permit.Signature, permit.ServerKeyVersion,
	); err != nil {
		// The verifier's message names the failing step and sometimes the key
		// version; neither belongs in a reply to a caller that just failed to
		// prove authorization.
		return chatStateNotAuthorized(d, "signature"), false
	}
	return proto.BaseResponse{}, true
}

// decodeChatStateRequest applies the size cap, the strict decode, and the
// request's own Validate. These requests are bound into a server signature, so
// they decode through strictDecodeJSON rather than the dispatcher's shared
// json.Unmarshal: a duplicate `conversation_id` would otherwise verify against
// one value and advance the chain of another.
func decodeChatStateRequest(payload json.RawMessage, req proto.Validator) (proto.BaseResponse, bool) {
	return decodeChatStateRequestCapped(payload, req, proto.ChatStateMaxRequestBytes)
}

func decodeChatStateRequestCapped(payload json.RawMessage, req proto.Validator, maxBytes int) (proto.BaseResponse, bool) {
	if len(payload) > maxBytes {
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
	case errors.Is(err, mls.ErrLeafUntrusted):
		return mlsLeafUntrustedResponse(d, stage, err)
	case errors.Is(err, errAttestationRefused):
		return chatStateNotAuthorized(d, "commit attestation")
	case errors.Is(err, mls.ErrUnavailable):
		code, message = proto.ChatMLSErrorCodeCapabilityRequired,
			"this Keeper was built without the MLS library"
	case errors.Is(err, chatstate.ErrCommitPending):
		code, message = proto.ChatMLSErrorCodeCommitPending,
			"a commit from this device is waiting for its outcome; confirm it first"
	case errors.Is(err, chatstate.ErrEpochStale):
		code, message = proto.ChatMLSErrorCodeEpochStale,
			"the request was built for another epoch than the one this device is on"
	case errors.Is(err, chatstate.ErrHandshakeApplied):
		code, message = proto.ChatMLSErrorCodeEpochStale,
			"that handshake is already applied on this device"
	case errors.Is(err, chatstate.ErrHandshakeSkipped):
		code, message = proto.ChatMLSErrorCodeEpochStale,
			"an earlier handshake has not been applied on this device"
	case errors.Is(err, chatstate.ErrNoGroupState):
		code, message = proto.ChatMLSErrorCodeFailed,
			"this device holds no group for this conversation"
	case errors.Is(err, chatstate.ErrGroupExists):
		code, message = proto.ChatStateErrorCodeConflict,
			"this device already holds a group for this conversation"
	case errors.Is(err, chatstate.ErrNoPendingCommit):
		code, message = proto.ChatStateErrorCodeConflict,
			"this device has no pending commit to settle"
	case errors.Is(err, chatstate.ErrCommitMismatch):
		code, message = proto.ChatStateErrorCodeConflict,
			"the pending commit on this device has another client_commit_id"
	case errors.Is(err, mls.ErrNoKeyPackageForWelcome):
		code, message = proto.ChatMLSErrorCodeWelcomeUnusable,
			"this device holds no key package the welcome is addressed to; it has to be invited again"
	case errors.Is(err, mls.ErrGroupMismatch):
		code, message = proto.ChatMLSErrorCodeFailed,
			"the welcome is for a different conversation"
	case errors.Is(err, chatstate.ErrHistoryUnavailable):
		code, message = proto.ChatMLSErrorCodeFailed,
			"this device has no usable local copy of that message"
	case errors.Is(err, chatstate.ErrNotUnacceptedCreate):
		code, message = proto.ChatStateErrorCodeConflict,
			"the group on this device is not an unaccepted create of this device"
	case errors.Is(err, chatstate.ErrNotRemoved):
		code, message = proto.ChatStateErrorCodeConflict,
			"this device was not removed from the group it holds for this conversation"
	case errors.Is(err, chatstate.ErrSeqBound):
		code, message = proto.ChatStateErrorCodeConflict,
			"that seq or that message is already bound to another one"
	case errors.Is(err, chatstate.ErrRoomNameUnopenable):
		code, message = proto.ChatMLSErrorCodeFailed,
			"the room name does not open under this epoch's key"
	case errors.Is(err, chatstate.ErrNotHandshake),
		errors.Is(err, chatstate.ErrOwnMessage),
		errors.Is(err, chatstate.ErrNotApplication),
		errors.Is(err, chatstate.ErrDeclarationMismatch),
		errors.Is(err, chatstate.ErrGenerationUnknown),
		errors.Is(err, chatstate.ErrBurnForward),
		errors.Is(err, mls.ErrFailed):
		code, message = proto.ChatMLSErrorCodeFailed, "the mls operation failed; nothing was applied"
	case errors.Is(err, chatstate.ErrRotationPending):
		code, message = proto.ChatMLSErrorCodeRotationPending,
			"a member removal is not yet applied on this device; new messages cannot be encrypted"
	case errors.Is(err, chatstate.ErrLeafReplacementPending):
		code, message = proto.ChatMLSErrorCodeLeafReplacementPending,
			"a device takeover is not yet applied on this device; new messages cannot be encrypted"
	case errors.Is(err, chatstate.ErrReplacementNotListed):
		code, message = proto.ChatStateErrorCodeInvalidInput,
			"the replace names a replacement this permit does not list"
	case errors.Is(err, chatstate.ErrRekeyRequired):
		var latched *chatstate.RekeyLatchedError
		if errors.As(err, &latched) {
			return rekeyLatchedResponse(d, stage, latched.Detail)
		}
		code, message = proto.ChatStateErrorCodeRekeyRequired,
			"chat state is behind its anchor; the conversation needs a new epoch"
	case errors.Is(err, chatstate.ErrCommitUnauthorized):
		code, message = proto.ChatMLSErrorCodeCommitUnauthorized,
			"the commit carries an add or a remove this device is not authorized to make; nothing was built"
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

// rekeyLatchedResponse is CHAT_STATE_REKEY_REQUIRED from the operation that
// set an unauthorized_commit or fork latch, carrying what it was about, so the
// app can say why without a second call. Later operations answer the bare
// code, and mls_conversation_status carries the same detail.
func rekeyLatchedResponse(d Deps, stage string, detail chatstate.RekeyDetail) proto.BaseResponse {
	d.Logger.Printf("chat state %s failed: %s (%s)", stage, proto.ChatStateErrorCodeRekeyRequired, detail.Cause)
	resp := errs.CodeResponse(errs.ErrorCode(proto.ChatStateErrorCodeRekeyRequired),
		"this device refused what the server served for the conversation and latched it read-only; nothing was applied")
	resp.Data = proto.ChatStateRekeyLatchedData{
		RekeyCause:              string(detail.Cause),
		RekeyEpoch:              detail.Epoch,
		RekeyCommitterAccountID: detail.CommitterAccountID,
		RekeyCommitterDeviceID:  detail.CommitterDeviceID,
	}
	return resp
}

// mlsLeafUntrustedResponse is CHAT_MLS_LEAF_UNTRUSTED. When the refusal was a
// changed account key it carries both fingerprints, as peer_key_changed does,
// so the UI can offer §5.5's three paths without asking the server for the
// very key the refusal is about. The reason names a condition, never a value.
func mlsLeafUntrustedResponse(d Deps, stage string, err error) proto.BaseResponse {
	d.Logger.Printf("chat state %s failed: %s", stage, proto.ChatMLSErrorCodeLeafUntrusted)
	resp := errs.CodeResponse(
		errs.ErrorCode(proto.ChatMLSErrorCodeLeafUntrusted),
		"a leaf entering the group is not vouched for by its account; nothing was applied",
	)
	var detail *MLSLeafUntrustedError
	if errors.As(err, &detail) && detail.ObservedFingerprint != "" {
		resp.Data = proto.PeerKeyChangedResponseData{
			ObservedFingerprint: detail.ObservedFingerprint,
			PinnedFingerprint:   detail.PinnedFingerprint,
		}
	}
	return resp
}
