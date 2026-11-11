package handlers

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleChatStatePurgeUnversioned erases an account's chat state that no
// sign-in owns and no generation names (lv78 A3; see
// proto.ChatStatePurgeUnversioned).
//
// The evidence and the erase share one hold of the keychain process lock,
// the lock SetAccountBinding and CommitChatLogin write the slot and the
// binding under, so a sign-in cannot land between the check and the erase.
// Both conditions are needed: "no slot" alone also holds for a 0.0.58 binding
// restored without renew, whose session is live on that state.
func HandleChatStatePurgeUnversioned(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.ChatStatePurgeUnversionedRequest
	if resp, ok := decodeChatStateRequest(payload, &req); !ok {
		return resp
	}
	var (
		removed int
		purged  bool
		kept    string
	)
	err := keychain.WithKeychainProcessLock(d.Store, func() error {
		login, err := keychain.ReadChatLogin(d.Store)
		if err != nil {
			return err
		}
		// An interrupted chat login may be about to give an account its slot
		// and binding; nothing is decided until it finishes.
		if login.Committing {
			return keychain.ErrChatLoginStale
		}
		generation, err := keychain.GetChatStateGeneration(d.Store, req.OwnerAccountID)
		if err != nil {
			return err
		}
		if generation != "" {
			kept = proto.ChatStatePurgeKeptGeneration
			return nil
		}
		binding, bound, err := keychain.GetAccountBinding(d.Store)
		if err != nil {
			return err
		}
		if bound && binding.AccountID == req.OwnerAccountID && !binding.SignedOut {
			kept = proto.ChatStatePurgeKeptSignedIn
			return nil
		}
		removed, err = chatstate.Purge(d.Store, req.OwnerAccountID)
		purged = err == nil
		return err
	})
	if err != nil {
		resp := chatStateFailure(d, "unversioned purge", err)
		if errors.Is(err, chatstate.ErrPurgeIncomplete) {
			resp.Data = proto.ChatStatePurgeResponseData{
				RemovedConversations: removed, EraseIncomplete: true,
			}
		}
		return resp
	}
	d.Logger.Printf("chat state unversioned purge finished: purged=%t conversations=%d kept=%s", purged, removed, kept)
	return proto.BaseResponse{Success: true, Data: proto.ChatStatePurgeResponseData{
		RemovedConversations: removed, Purged: purged, Kept: kept,
	}}
}
