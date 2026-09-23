// mls_chat.go — the MLS chat v2 actions at the protocol edge.
//
// Every action here runs, in order:
//
//	the chat-state gate (size cap → strict decode → validation → binding →
//	  permit window → server signature), exactly authorizeChatState's
//	  → the MLS library is linked
//	  → the permit owner's store opens and the watermark names this leaf
//	  → the device session opens as the active leaf, which must belong to
//	    the permit's account
//	  → one chatstate transaction, with every leaf it brings in verified
//	  → only after that transaction is on disk, the verifier's pins and
//	    newest-declaration records are written
//
// so a refusal at any step persists nothing, and an unauthorized caller does
// not even open the state directory.
//
// Nothing here logs a group state, a Commit, a Welcome, a plaintext or the
// length of any of them. The group state holds this device's leaf signature
// secret key.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// mlsChat is one action's opened context. close releases the session and the
// store's derived keys.
type mlsChat struct {
	store   *chatstate.Store
	wm      chatstate.ServerWatermark
	session *mls.Session
	leaf    mls.DeviceLeaf
	permit  proto.ChatStatePermit
	conv    string
}

func (c *mlsChat) close() {
	c.session.Close()
	c.store.Close()
}

// openMLSChat runs the whole gate and returns an opened context only when every
// step passed, so no handler can reach the store or the leaf key by skipping
// one.
func openMLSChat(
	d Deps, payload json.RawMessage, req proto.ChatStateBound, maxBytes int,
) (*mlsChat, proto.BaseResponse, bool) {
	if resp, ok := authorizeChatStateCapped(d, payload, req, maxBytes); !ok {
		return nil, resp, false
	}
	if !mls.Available() {
		return nil, errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeCapabilityRequired),
			"this Keeper was built without the MLS library"), false
	}
	permit, _, conversationID := req.ChatStateContext()
	store, wm, resp, ok := openChatStateStore(d, permit, conversationID)
	if !ok {
		return nil, resp, false
	}
	session, leaf, err := mls.NewDeviceSession(d.Store)
	if err != nil {
		store.Close()
		return nil, mlsSessionFailure(d, err), false
	}
	// The permit says whose chain this is; the leaf says who signs. A leaf of
	// another account would put that account's name on this account's
	// messages.
	if leaf.AccountID != permit.AccountID {
		session.Close()
		store.Close()
		return nil, chatStateNotAuthorized(d, "leaf account"), false
	}
	return &mlsChat{store: store, wm: wm, session: session, leaf: leaf, permit: permit, conv: conversationID}, proto.BaseResponse{}, true
}

func mlsSessionFailure(d Deps, err error) proto.BaseResponse {
	d.Logger.Println("mls chat: the device session could not be opened")
	message := "mls device session could not be opened"
	switch {
	case errors.Is(err, mls.ErrNoLeafKey), errors.Is(err, mls.ErrNoLeafDeclaration):
		message = "no active mls leaf key; mls_leaf_declare enroll and promote first"
	case errors.Is(err, mls.ErrLeafKeyUnreadable):
		message = "mls leaf key record is unreadable"
	}
	return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeFailed), message)
}

func (c *mlsChat) verifier(d Deps, statements []proto.KeyRotationStatement) *MLSLeafVerifier {
	return NewMLSLeafVerifier(d, c.permit.AccountID, statementsByAccount(statements))
}

func statementsByAccount(statements []proto.KeyRotationStatement) map[string][]proto.KeyRotationStatement {
	if len(statements) == 0 {
		return nil
	}
	out := map[string][]proto.KeyRotationStatement{}
	for _, s := range statements {
		out[s.AccountID] = append(out[s.AccountID], s)
	}
	return out
}

// commitVerified writes what the verifier staged, once the chatstate write it
// was for is on disk. A failure here is reported rather than swallowed: the
// group moved, but a pin that was not saved is a first use the next time.
func commitVerified(d Deps, stage string, v *MLSLeafVerifier) (proto.BaseResponse, bool) {
	if err := v.Commit(); err != nil {
		d.Logger.Printf("mls chat %s: the verified leaves could not be recorded", stage)
		return errs.CodeResponse(errs.ErrorCode(proto.ChatStateErrorCodeStorageFailure),
			"the group moved but its verified leaves could not be recorded"), false
	}
	return proto.BaseResponse{}, true
}

// memberKeyPackages decodes the KeyPackages and refuses any whose credential
// is not the account and device the caller asked the server for. Validate has
// already bounded and Base64-checked each one.
func memberKeyPackages(d Deps, members []proto.MLSMemberKeyPackage) ([][]byte, proto.BaseResponse, bool) {
	out := make([][]byte, 0, len(members))
	for _, m := range members {
		kp, err := base64.StdEncoding.DecodeString(m.KeyPackageB64)
		if err != nil {
			return nil, chatStateInvalidInput("key_package_b64 must be valid standard Base64"), false
		}
		account, device, err := mls.KeyPackageIdentity(kp)
		if err != nil {
			return nil, chatStateFailure(d, "key package identity", err), false
		}
		if account != m.AccountID || device != m.DeviceID {
			return nil, mlsLeafUntrustedResponse(d, "key package identity",
				untrusted("key package names a different account or device than the one requested")), false
		}
		out = append(out, kp)
	}
	return out, proto.BaseResponse{}, true
}

func commitResponse(r chatstate.BeginCommitResult) proto.BaseResponse {
	data := proto.MLSCommitResponseData{
		ClientCommitID:    r.ClientCommitID,
		ExpectedEpoch:     r.ExpectedEpoch,
		CommitB64:         base64.StdEncoding.EncodeToString(r.Commit),
		WelcomeB64:        base64.StdEncoding.EncodeToString(r.Welcome),
		WelcomeReleasable: r.WelcomeReleasable,
		Created:           r.Created,
		Generation:        r.Generation,
	}
	if r.RoomName != nil {
		data.NameEpoch = r.RoomName.Epoch
		data.NameIVb64 = base64.StdEncoding.EncodeToString(r.RoomName.IV)
		data.NameCiphertextB64 = base64.StdEncoding.EncodeToString(r.RoomName.Ciphertext)
	}
	return proto.BaseResponse{Success: true, Data: data}
}

// roomNameInput decodes an optional room name. Nil means none was given; the
// caller wipes a non-nil result.
func roomNameInput(b64 string) ([]byte, proto.BaseResponse, bool) {
	if b64 == "" {
		return nil, proto.BaseResponse{}, true
	}
	name, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, chatStateInvalidInput("the room name must be valid standard Base64"), false
	}
	if !utf8.Valid(name) {
		secure.Zeroize(name)
		return nil, chatStateInvalidInput("the room name must decode to UTF-8 text"), false
	}
	return name, proto.BaseResponse{}, true
}

// ────────────────────────────────────────────────────────────────────────
// Membership and handshake.
// ────────────────────────────────────────────────────────────────────────

// HandleMLSGroupCreate creates the conversation's group and builds the pending
// Add for its first members, in one chatstate transaction.
func HandleMLSGroupCreate(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSGroupCreateRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSChatMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	kps, resp, ok := memberKeyPackages(d, req.Members)
	if !ok {
		return resp
	}
	name, resp, ok := roomNameInput(req.RoomNamePlaintextB64)
	if !ok {
		return resp
	}
	defer secure.Zeroize(name)
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.CreateGroup(c.conv, c.wm, chatstate.BeginCommitRequest{
		ClientCommitID: req.ClientCommitID,
		Plan:           chatstate.CommitPlan{AddKeyPackages: kps},
		RoomName:       name,
	}, mls.NewCipher(c.session, v))
	if err != nil {
		return chatStateFailure(d, "mls group create", err)
	}
	if resp, ok := commitVerified(d, "group create", v); !ok {
		return resp
	}
	d.Logger.Println("mls group create successful")
	return commitResponse(result)
}

// HandleMLSGroupDiscardUnaccepted drops this device's create that lost the
// race for the conversation's first epoch (chatstate.DiscardUnacceptedGroup).
func HandleMLSGroupDiscardUnaccepted(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSGroupDiscardUnacceptedRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	result, err := c.store.DiscardUnacceptedGroup(c.conv, c.wm, req.ClientCommitID)
	if err != nil {
		return chatStateFailure(d, "mls group discard", err)
	}
	d.Logger.Println("mls group discard successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSGroupDiscardUnacceptedResponseData{
		Discarded:  result.Discarded,
		Generation: result.Generation,
	}}
}

// replaceMembers decodes the replace entries and pairs each with the key the
// permit names for its account. The credential is checked against the account
// here, as memberKeyPackages checks an Add's; the key is checked against the
// permit where the Commit is built (mls.Cipher.BuildCommit). Validate has
// already required every account to be listed.
func replaceMembers(
	d Deps, members []proto.MLSReplaceMember, listed []proto.ChatStateLeafReplacement,
) ([]chatstate.ReplaceMember, proto.BaseResponse, bool) {
	out := make([]chatstate.ReplaceMember, 0, len(members))
	for _, m := range members {
		kp, err := base64.StdEncoding.DecodeString(m.KeyPackageB64)
		if err != nil {
			return nil, chatStateInvalidInput("key_package_b64 must be valid standard Base64"), false
		}
		account, _, err := mls.KeyPackageIdentity(kp)
		if err != nil {
			return nil, chatStateFailure(d, "key package identity", err), false
		}
		if account != m.AccountID {
			return nil, mlsLeafUntrustedResponse(d, "key package identity",
				untrusted("key package names a different account than the one being replaced")), false
		}
		entry, ok := proto.LeafReplacementFor(listed, m.AccountID)
		if !ok {
			return nil, chatStateInvalidInput("replace names an account the permit does not list"), false
		}
		out = append(out, chatstate.ReplaceMember{
			AccountID: m.AccountID, NewFingerprint: entry.NewSignatureKeyFP, KeyPackage: kp,
		})
	}
	return out, proto.BaseResponse{}, true
}

// HandleMLSCommitBuild builds one pending Commit: an Add, a Remove, a replace
// (design M4.4), or an Update of this device's own leaf.
func HandleMLSCommitBuild(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSCommitBuildRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSChatMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	// Validate has already required exactly one kind. An empty plan is the
	// Update, which is how chatstate.CommitPlan spells it.
	var plan chatstate.CommitPlan
	switch {
	case req.Add != nil:
		kps, resp, ok := memberKeyPackages(d, req.Add)
		if !ok {
			return resp
		}
		plan.AddKeyPackages = kps
	case req.RemoveAccountIDs != nil:
		plan.RemoveAccountIDs = req.RemoveAccountIDs
	case req.Replace != nil:
		members, resp, ok := replaceMembers(d, req.Replace, req.Permit.PendingLeafReplacements)
		if !ok {
			return resp
		}
		plan.Replace = members
	}
	name, resp, ok := roomNameInput(req.RoomNamePlaintextB64)
	if !ok {
		return resp
	}
	defer secure.Zeroize(name)
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.BeginCommit(c.conv, c.wm, chatstate.BeginCommitRequest{
		ClientCommitID: req.ClientCommitID,
		Plan:           plan,
		ExpectedEpoch:  req.ExpectedEpoch,
		RoomName:       name,
	}, mls.NewCipher(c.session, v))
	if err != nil {
		return chatStateFailure(d, "mls commit build", err)
	}
	if resp, ok := commitVerified(d, "commit build", v); !ok {
		return resp
	}
	d.Logger.Println("mls commit build successful")
	return commitResponse(result)
}

// HandleMLSCommitConfirm applies the server's CAS verdict, or, for unknown,
// reports the pending Commit so the caller can ask the server about it.
func HandleMLSCommitConfirm(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSCommitConfirmRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSChatMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	if req.Outcome == proto.MLSCommitOutcomeUnknown {
		pending, found, err := c.store.PendingCommit(c.conv, c.wm)
		if err == nil && !found {
			err = chatstate.ErrNoPendingCommit
		}
		if err == nil && pending.ClientCommitID != req.ClientCommitID {
			err = chatstate.ErrCommitMismatch
		}
		if err != nil {
			return chatStateFailure(d, "mls commit confirm", err)
		}
		return proto.BaseResponse{Success: true, Data: proto.MLSCommitConfirmResponseData{
			Outcome:   req.Outcome,
			Epoch:     pending.ExpectedEpoch,
			CommitB64: base64.StdEncoding.EncodeToString(pending.Commit),
		}}
	}

	outcome := chatstate.CommitOutcome{ClientCommitID: req.ClientCommitID, Kind: chatstate.CommitAccepted}
	if req.Outcome == proto.MLSCommitOutcomeSuperseded {
		winner, err := base64.StdEncoding.DecodeString(req.WinnerCommitB64)
		if err != nil {
			return chatStateInvalidInput("winner_commit_b64 must be valid standard Base64")
		}
		outcome.Kind, outcome.WinnerMessage = chatstate.CommitSuperseded, winner
	}
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.ConfirmCommit(c.conv, c.wm, outcome, mls.NewCipher(c.session, v))
	if err != nil {
		return chatStateFailure(d, "mls commit confirm", err)
	}
	if resp, ok := commitVerified(d, "commit confirm", v); !ok {
		return resp
	}
	d.Logger.Println("mls commit confirm successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSCommitConfirmResponseData{
		Outcome:           req.Outcome,
		Epoch:             result.Epoch,
		WelcomeReleasable: result.WelcomeReleasable,
		Removed:           result.Removed,
		Generation:        result.Generation,
	}}
}

// HandleMLSProcess applies one handshake row: somebody else's Commit.
func HandleMLSProcess(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSProcessRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSChatMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	commit, err := base64.StdEncoding.DecodeString(req.CommitB64)
	if err != nil {
		return chatStateInvalidInput("commit_b64 must be valid standard Base64")
	}
	// Every Commit this integration sends is a PublicMessage
	// (encrypt_control_messages is pinned false), and an application message
	// belongs to the display path, where it is recorded in the history.
	if form, err := mls.WireFormOf(commit); err != nil || form != mls.WireFormPublicMessage {
		return chatStateInvalidInput("commit_b64 is not an MLS PublicMessage")
	}
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.Receive(c.conv, c.wm, chatstate.ReceiveRequest{
		Seq:           req.Seq,
		Message:       commit,
		Handshake:     true,
		ProducedEpoch: req.Epoch,
	}, mls.NewCipher(c.session, v))
	if err != nil {
		return chatStateFailure(d, "mls process", err)
	}
	if resp, ok := commitVerified(d, "process", v); !ok {
		return resp
	}
	d.Logger.Println("mls process successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSProcessResponseData{
		Seq:        req.Seq,
		Epoch:      result.Position.Epoch,
		Removed:    result.Removed,
		Generation: result.Generation,
	}}
}

// HandleMLSJoin joins the conversation's group from a Welcome.
func HandleMLSJoin(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSJoinRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSChatMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	welcome, err := base64.StdEncoding.DecodeString(req.WelcomeB64)
	if err != nil {
		return chatStateInvalidInput("welcome_b64 must be valid standard Base64")
	}
	v := c.verifier(d, req.RotationStatements)
	if err := c.session.JoinFromPool(c.store, c.conv, c.wm, welcome, v, d.Now()); err != nil {
		return chatStateFailure(d, "mls join", err)
	}
	if resp, ok := commitVerified(d, "join", v); !ok {
		return resp
	}
	epoch, err := c.session.Epoch()
	if err != nil {
		return chatStateFailure(d, "mls join", err)
	}
	d.Logger.Println("mls join successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSJoinResponseData{Epoch: epoch}}
}

// ────────────────────────────────────────────────────────────────────────
// Messages.
//
// mls_decrypt_batch_for_app_display widens the v1 reveal's carve-out
// (conversation_decrypt.go) instead of adding one, and keeps its gates except
// the ones that belong to a key the server held:
//
//	kept     a server-signed permit checked for binding, window and signature
//	         before anything is opened (the conversation-state permit here)
//	kept     strict decode and a request cap, at most 200 messages, each
//	         ciphertext bounded to the 8208 bytes the server stores
//	kept     the caller says nothing about binding: no AAD, no key, no
//	         position. MLS framing and the sender's declaration, checked
//	         against the generation the library derived, take the AAD's place
//	kept     every plaintext is well-formed UTF-8
//	kept     one failure refuses the whole batch with no partial plaintext,
//	         and here also with nothing written
//	kept     every plaintext buffer is zeroized, nothing about one is logged
//	dropped  the read permit (dragpass.chat.read): decision R2, the Keeper
//	         opens these with MLS keys the server never held, so there is no
//	         server key possession to authorize
//	dropped  the group handle: it proved the caller held the conversation
//	         DEK; here the key never leaves the Keeper's own group state
//	dropped  dek_version binding and payload_kind: the epoch is inside the
//	         MLS framing, and room names are not on this path
// ────────────────────────────────────────────────────────────────────────

var errDisplayNotText = errors.New("mls display plaintext is not UTF-8")

// HandleMLSEncrypt encrypts one application message through chatstate.Send:
// the position is consumed, encrypted at and persisted in one locked section.
func HandleMLSEncrypt(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSEncryptRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	defer secure.Zeroize(plaintext)
	if err != nil {
		return chatStateInvalidInput("plaintext_b64 must be valid standard Base64")
	}
	// The display path refuses a plaintext that is not text, so a message
	// that is not would be sent and never shown.
	if !utf8.Valid(plaintext) {
		return chatStateInvalidInput("plaintext_b64 must decode to UTF-8 text")
	}
	result, err := c.store.Send(c.conv, c.wm, chatstate.SendRequest{
		ClientMessageID: req.ClientMessageID,
		Plaintext:       plaintext,
		ExpectedEpoch:   req.ExpectedEpoch,
	}, mls.NewCipher(c.session, c.verifier(d, nil)))
	if err != nil {
		return chatStateFailure(d, "mls encrypt", err)
	}
	d.Logger.Println("mls encrypt successful")
	pos := result.Entry.Position
	return proto.BaseResponse{Success: true, Data: proto.MLSEncryptResponseData{
		ClientMessageID: result.Entry.ClientMessageID,
		CiphertextB64:   base64.StdEncoding.EncodeToString(result.Entry.Ciphertext),
		Epoch:           pos.Epoch,
		LeafIndex:       pos.SenderLeafIndex,
		ContentType:     string(pos.ContentType),
		Generation:      pos.Generation,
		Created:         result.Created,
	}}
}

// HandleMLSMarkSent binds a sent message's sealed copy to the server's seq.
func HandleMLSMarkSent(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSMarkSentRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	result, err := c.store.MarkSent(c.conv, c.wm, req.ClientMessageID, req.Seq)
	if err != nil {
		return chatStateFailure(d, "mls mark sent", err)
	}
	d.Logger.Println("mls mark sent successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSMarkSentResponseData{
		ClientMessageID: req.ClientMessageID,
		Seq:             req.Seq,
		Bound:           result.Bound,
		Generation:      result.Generation,
	}}
}

// HandleMLSDecryptBatchForAppDisplay opens a page of application messages
// for the app's own screen, all or nothing but for a message of this device
// that has no local copy (chatstate.ReceiveBatch).
func HandleMLSDecryptBatchForAppDisplay(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSDecryptBatchForAppDisplayRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.MLSDecryptMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	reqs := make([]chatstate.ReceiveRequest, 0, len(req.Messages))
	for _, m := range req.Messages {
		ciphertext, err := base64.StdEncoding.DecodeString(m.CiphertextB64)
		if err != nil {
			return chatStateInvalidInput("ciphertext_b64 must be valid standard Base64")
		}
		// Commits are applied through mls_process, in epoch order; only an
		// application message belongs on this path.
		if form, err := mls.WireFormOf(ciphertext); err != nil || form != mls.WireFormPrivateMessage {
			return chatStateInvalidInput("ciphertext_b64 is not an MLS PrivateMessage")
		}
		reqs = append(reqs, chatstate.ReceiveRequest{Seq: m.Seq, Message: ciphertext})
	}
	acceptText := func(plaintext []byte) error {
		if !utf8.Valid(plaintext) {
			return errDisplayNotText
		}
		return nil
	}
	results, err := c.store.ReceiveBatch(c.conv, c.wm, reqs, acceptText, mls.NewCipher(c.session, c.verifier(d, nil)))
	defer func() {
		for _, r := range results {
			secure.Zeroize(r.Plaintext)
		}
	}()
	if errors.Is(err, errDisplayNotText) {
		d.Logger.Println("mls decrypt batch refused a plaintext that is not text")
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeFailed),
			"a message is not text; nothing was shown or written")
	}
	if err != nil {
		return chatStateFailure(d, "mls decrypt batch", err)
	}

	plaintexts := make([]string, len(results))
	items := make([]proto.MLSDisplayItem, len(results))
	for i, r := range results {
		if r.OwnWithoutCopy {
			items[i] = proto.MLSDisplayItem{
				Seq:             req.Messages[i].Seq,
				State:           proto.MLSDisplayItemStateOwnWithoutCopy,
				SenderAccountID: c.leaf.AccountID,
				SenderDeviceID:  c.leaf.DeviceID,
			}
			continue
		}
		// A copy that cannot say who sent it is refused rather than shown
		// under nobody's name.
		if r.Sender.AccountID == "" || r.Sender.DeviceID == "" {
			return chatStateFailure(d, "mls decrypt batch", chatstate.ErrHistoryUnavailable)
		}
		plaintexts[i] = base64.StdEncoding.EncodeToString(r.Plaintext)
		items[i] = proto.MLSDisplayItem{
			Seq:             req.Messages[i].Seq,
			State:           proto.MLSDisplayItemStateShown,
			SenderAccountID: r.Sender.AccountID,
			SenderDeviceID:  r.Sender.DeviceID,
			Epoch:           r.Position.Epoch,
			SenderLeafIndex: r.Position.SenderLeafIndex,
			ContentType:     string(r.Position.ContentType),
			Generation:      r.Position.Generation,
			FromHistory:     r.FromHistory,
		}
	}
	d.Logger.Println("mls decrypt batch successful")
	return proto.BaseResponse{Success: true, Data: proto.ConversationDecryptBatchForAppDisplayResponseData{
		PlaintextB64: plaintexts,
		Items:        items,
	}}
}

// ────────────────────────────────────────────────────────────────────────
// Room names (chatstate/roomname.go).
//
// mls_room_name_open returns its name through the display batch's response
// type and its one plaintext field, as the v1 reveal does for
// payload_kind=room_name: the carve-out is widened, not added. The gates are
// the display batch's — a server-signed permit before anything is opened, a
// Keeper-built AAD, UTF-8, zeroized buffers, nothing logged — and the key is
// the confirmed epoch's MLS exporter, which the server never held.
// ────────────────────────────────────────────────────────────────────────

// HandleMLSRoomNameSeal seals a room name under the confirmed epoch.
func HandleMLSRoomNameSeal(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSRoomNameSealRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	name, resp, ok := roomNameInput(req.PlaintextB64)
	if !ok {
		return resp
	}
	defer secure.Zeroize(name)
	sealed, err := c.store.SealRoomName(c.conv, c.wm, name, mls.NewCipher(c.session, nil))
	if err != nil {
		return chatStateFailure(d, "mls room name seal", err)
	}
	d.Logger.Println("mls room name seal successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSRoomNameSealResponseData{
		Epoch:             sealed.Epoch,
		NameIVb64:         base64.StdEncoding.EncodeToString(sealed.IV),
		NameCiphertextB64: base64.StdEncoding.EncodeToString(sealed.Ciphertext),
	}}
}

// HandleMLSRoomNameOpen opens a room name sealed for the confirmed epoch.
func HandleMLSRoomNameOpen(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSRoomNameOpenRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	iv, err := base64.StdEncoding.DecodeString(req.NameIVb64)
	if err != nil {
		return chatStateInvalidInput("name_iv_b64 must be valid standard Base64")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.NameCiphertextB64)
	if err != nil {
		return chatStateInvalidInput("name_ciphertext_b64 must be valid standard Base64")
	}
	name, err := c.store.OpenRoomName(c.conv, c.wm, req.Epoch, iv, ciphertext, mls.NewCipher(c.session, nil))
	defer secure.Zeroize(name)
	if err != nil {
		return chatStateFailure(d, "mls room name open", err)
	}
	if !utf8.Valid(name) {
		d.Logger.Println("mls room name open refused a name that is not text")
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeFailed), "the room name is not text")
	}
	d.Logger.Println("mls room name open successful")
	return proto.BaseResponse{Success: true, Data: proto.ConversationDecryptBatchForAppDisplayResponseData{
		PlaintextB64: []string{base64.StdEncoding.EncodeToString(name)},
	}}
}

// ────────────────────────────────────────────────────────────────────────
// Status.
// ────────────────────────────────────────────────────────────────────────

// HandleMLSConversationStatus reports the conversation's state without
// changing it.
func HandleMLSConversationStatus(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSConversationStatusRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	status, err := c.store.Status(c.conv, c.wm, mls.NewCipher(c.session, nil))
	if err != nil {
		return chatStateFailure(d, "mls conversation status", err)
	}
	return proto.BaseResponse{Success: true, Data: proto.MLSConversationStatusResponseData{
		Epoch:                 status.Epoch,
		HasGroupState:         status.HasGroupState,
		CommitPending:         status.CommitPending,
		PendingClientCommitID: status.PendingClientCommitID,
		RemovalLatch:          status.RemovalLatch,
		LeafReplacementLatch:  permitLeafReplacements(status.LeafReplacementLatch),
		NeedsRekey:            status.NeedsRekey,
	}}
}

func permitLeafReplacements(entries []chatstate.LeafReplacement) []proto.ChatStateLeafReplacement {
	out := make([]proto.ChatStateLeafReplacement, len(entries))
	for i, e := range entries {
		out[i] = proto.ChatStateLeafReplacement{AccountID: e.AccountID, NewSignatureKeyFP: e.NewFingerprint}
	}
	return out
}
