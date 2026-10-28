package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/dragpass/keeper/config"
)

const chatLoginSlot = "chat_login_fence_v1"

var ErrChatLoginStale = errors.New("chat login intent superseded")

// ChatLoginState is concurrency state, not an account authentication proof.
// The paired App still verifies its account key and every permit is checked.
type ChatLoginState struct {
	Committing          bool   `json:"committing"`
	CommitAccountID     string `json:"commit_account_id"`
	Version             int    `json:"v"`
	Generation          string `json:"generation"`
	IntentID            string `json:"intent_id"`
	AccountID           string `json:"account_id"`
	PendingID           string `json:"pending_id"`
	PendingGeneration   string `json:"pending_generation"`
	PendingPredecessor  string `json:"pending_predecessor"`
	PreparationSequence uint64 `json:"preparation_sequence"`
}

func ReadChatLogin(store SecretStore) (ChatLoginState, error) {
	raw, err := store.Get(config.Service, chatLoginSlot)
	if errors.Is(err, ErrSecretNotFound) {
		return ChatLoginState{}, nil
	}
	if err != nil {
		return ChatLoginState{}, err
	}
	var state ChatLoginState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return state, err
	}
	if state.Version != 1 {
		return ChatLoginState{}, errors.New("invalid chat login state")
	}
	return state, nil
}

func saveChatLogin(store SecretStore, state ChatLoginState) error {
	state.Version = 1
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return store.Set(config.Service, chatLoginSlot, string(raw))
}

// PrepareChatLogin never rebases a known intent on another predecessor.
func PrepareChatLogin(store SecretStore, id, predecessor string, after uint64) error {
	return withPersonalKeyBundleLock(store, func() error {
		state, err := ReadChatLogin(store)
		if err != nil {
			return err
		}
		if state.IntentID == id && state.Generation != "" && !state.Committing {
			return nil
		}
		if state.PendingID == id {
			if state.PendingPredecessor != predecessor || state.PreparationSequence != after+1 {
				return ErrChatLoginStale
			}
			return nil
		}
		if state.Committing || state.Generation != predecessor || state.PreparationSequence != after || after >= 9007199254740991 {
			return ErrChatLoginStale
		}
		state.PendingID, state.PendingGeneration, state.PendingPredecessor = id, newChatGeneration(), predecessor
		state.PreparationSequence++
		return saveChatLogin(store, state)
	})
}

// CommitChatLogin serializes the predecessor check, account incarnation and
// hint publication. The pending incarnation survives a lost write answer, so
// retrying the same intent never invents another incarnation.
func CommitChatLogin(store SecretStore, id, accountID, alias string) (ChatLoginState, bool, error) {
	var result ChatLoginState
	changed := false
	err := withPersonalKeyBundleLock(store, func() error {
		state, err := ReadChatLogin(store)
		if err != nil {
			return err
		}
		if state.IntentID == id && state.Generation != "" && !state.Committing {
			if state.AccountID != accountID {
				return ErrChatLoginStale
			}
			result = state
			return nil
		}
		generation := state.PendingGeneration
		if generation == "" || state.PendingID != id || state.Generation != state.PendingPredecessor {
			return ErrChatLoginStale
		}
		if state.Committing && state.CommitAccountID != accountID {
			return ErrChatLoginStale
		}
		// Publish an interrupted-transition fence before changing any comparison
		// slot. Admission and conditional purge both refuse it until commit finishes.
		state.Committing, state.CommitAccountID = true, accountID
		if err := saveChatLogin(store, state); err != nil {
			return err
		}
		current, _, err := GetAccountBinding(store)
		if err != nil {
			return err
		}
		if err := store.Set(config.Service, chatStateGenerationSlot(accountID), generation); err != nil {
			return err
		}
		next := AccountBinding{V: accountBindingVersion, AccountID: accountID, Alias: alias,
			Generation: current.Generation + 1}
		if current.AccountID == accountID && current.Alias == alias && !current.SignedOut && current.ChatStateGeneration == generation {
			next.Generation = current.Generation
		}
		if err := saveAccountBinding(store, next); err != nil {
			return err
		}
		state.Generation, state.IntentID, state.AccountID = generation, id, accountID
		state.Committing, state.CommitAccountID = false, ""
		state.PendingID, state.PendingGeneration, state.PendingPredecessor = "", "", ""
		if err := saveChatLogin(store, state); err != nil {
			return err
		}
		result, changed = state, true
		return nil
	})
	return result, changed, err
}

// ConsumeChatClaim persists a high-water mark; equal delivery is refused and
// can never rebind a grant to another local RPC session. The generation scopes
// the counter. Old local sessions cannot survive a process restart either.
func ConsumeChatClaim(store SecretStore, generation, holder string, sequence uint64) error {
	return withPersonalKeyBundleLock(store, func() error {
		state, err := ReadChatLogin(store)
		if err != nil {
			return err
		}
		if state.Committing {
			return ErrChatLoginStale
		}
		if state.Generation == "" {
			if generation == "" {
				return nil
			}
			return ErrChatLoginStale
		}
		if generation != state.Generation || sequence == 0 || sequence > 9007199254740991 {
			return ErrChatLoginStale
		}
		// Separate bounded-size slots preserve replay fences for every holder,
		// including tabs closed before another no-Web-Locks tab opens.
		identity, err := json.Marshal([]string{"dragpass.chat-claim.v1", generation, holder})
		if err != nil {
			return err
		}
		digest := sha256.Sum256(identity)
		slot := "chat_claim_v1_" + hex.EncodeToString(digest[:])
		raw, err := store.Get(config.Service, slot)
		previous := uint64(0)
		if err == nil {
			previous, err = strconv.ParseUint(raw, 10, 64)
			if err != nil || previous == 0 || previous > 9007199254740991 || strconv.FormatUint(previous, 10) != raw {
				return errors.New("invalid chat claim sequence")
			}
		} else if !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		if sequence <= previous {
			return ErrChatLoginStale
		}
		return store.Set(config.Service, slot, strconv.FormatUint(sequence, 10))
	})
}
