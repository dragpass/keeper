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

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// mlsChat is one action's opened context. close releases the session and the
// store's derived keys.
type mlsChat struct {
	store   *chatstate.Store
	wm      chatstate.ServerWatermark
	session *mls.Session
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
	return &mlsChat{store: store, wm: wm, session: session, permit: permit, conv: conversationID}, proto.BaseResponse{}, true
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
	return proto.BaseResponse{Success: true, Data: proto.MLSCommitResponseData{
		ClientCommitID:    r.ClientCommitID,
		ExpectedEpoch:     r.ExpectedEpoch,
		CommitB64:         base64.StdEncoding.EncodeToString(r.Commit),
		WelcomeB64:        base64.StdEncoding.EncodeToString(r.Welcome),
		WelcomeReleasable: r.WelcomeReleasable,
		Created:           r.Created,
		Generation:        r.Generation,
	}}
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
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.CreateGroup(c.conv, c.wm, chatstate.BeginCommitRequest{
		ClientCommitID: req.ClientCommitID,
		Plan:           chatstate.CommitPlan{AddKeyPackages: kps},
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

// HandleMLSCommitBuild builds one pending Commit: an Add, a Remove, or an
// Update of this device's own leaf.
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
	}
	v := c.verifier(d, req.RotationStatements)
	result, err := c.store.BeginCommit(c.conv, c.wm, chatstate.BeginCommitRequest{
		ClientCommitID: req.ClientCommitID,
		Plan:           plan,
		ExpectedEpoch:  req.ExpectedEpoch,
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
