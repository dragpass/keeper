package handlers

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// buildLoginGeneration is the chat login generation a Commit is built under,
// stored with it so that only the same sign-in may discard it after a
// refusal. Empty while a sign-in is committing or the state is unreadable:
// such a Commit is never discarded, only settled from the log.
func buildLoginGeneration(d Deps) string {
	state, err := keychain.ReadChatLogin(d.Store)
	if err != nil || state.Committing {
		return ""
	}
	return state.Generation
}

// HandleMLSCommitDiscardRefused drops this device's own pending Commit the
// server definitively refused (chatstate.DiscardRefusedCommit).
//
// No online decision: the discard releases nothing and uses no key outward,
// it only takes back a change the server would not apply, and the refusals
// it follows include the loss of the authority such a decision would need.
// It is bound locally instead: the permit, the chat runtime lease and login
// generation the gate checks, the Commit's own id and epoch, and the login
// generation it was built under, read together with the discard under the
// keychain process lock, so a sign-in cannot land between the two.
func HandleMLSCommitDiscardRefused(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSCommitDiscardRefusedRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	cipher := mls.NewCipher(c.session, c.verifier(d, nil))
	var result chatstate.DiscardResult
	err := keychain.WithKeychainProcessLock(d.Store, func() error {
		state, err := keychain.ReadChatLogin(d.Store)
		if err != nil {
			return err
		}
		generation := state.Generation
		if state.Committing {
			generation = ""
		}
		result, err = c.store.DiscardRefusedCommit(c.conv, c.wm, chatstate.RefusedCommitDiscard{
			ClientCommitID:  req.ClientCommitID,
			ExpectedEpoch:   req.ExpectedEpoch,
			LoginGeneration: generation,
		}, cipher)
		return err
	})
	if err != nil {
		return chatStateFailure(d, "mls commit discard refused", err)
	}
	d.Logger.Println("mls commit discard refused successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSCommitDiscardRefusedResponseData{
		Discarded:  result.Discarded,
		Generation: result.Generation,
	}}
}
