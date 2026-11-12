package proto

// ChatStatePurgeUnversioned erases one account's chat state that has no chat
// state generation (lv78 A3): state an older Keeper (0.0.58) wrote before it
// kept a generation slot, which chat_state_purge cannot name and so cannot
// erase. The App sends it for a pending sign-out cleanup whose generation it
// never learned.
//
// It is not a generation-less chat_state_purge. That action still refuses a
// request without expected_generation, and this one erases only on evidence
// read under the keychain process lock in the same hold as the erase: the
// account has no generation slot (no sign-in since the update named this
// state) and the binding is not that account's signed-in state (no live
// session runs on it). A state that has a slot is erased only by
// chat_state_purge with that generation. The request names both conditions,
// so it never stands for an unconditional erase.
//
//	Inputs: owner_account_id, require_no_generation (true),
//	        require_not_signed_in (true)
//	Output: { purged, removed_conversations, kept? }
const ChatStatePurgeUnversioned = "chat_state_purge_unversioned"

// Why an unversioned purge left the state in place. Each is a definite
// answer: the state is not erased and a retry gives the same answer until the
// evidence changes.
const (
	// ChatStatePurgeKeptGeneration: the account has a chat state generation,
	// so the state belongs to a sign-in a Keeper that names its sign-ins saw.
	ChatStatePurgeKeptGeneration = "generation_present"
	// ChatStatePurgeKeptSignedIn: the binding is this account, signed in; a
	// session may be running on the state.
	ChatStatePurgeKeptSignedIn = "account_signed_in"
)

// ChatStatePurgeUnversionedRequest names the account and states the two
// conditions the erase depends on. Both must be true.
type ChatStatePurgeUnversionedRequest struct {
	OwnerAccountID      string `json:"owner_account_id"`
	RequireNoGeneration bool   `json:"require_no_generation"`
	RequireNotSignedIn  bool   `json:"require_not_signed_in"`
}

func (r ChatStatePurgeUnversionedRequest) Validate() error {
	if !r.RequireNoGeneration {
		return newValidationError("require_no_generation", "must be true")
	}
	if !r.RequireNotSignedIn {
		return newValidationError("require_not_signed_in", "must be true")
	}
	return requireMessageUUID(r.OwnerAccountID, "owner_account_id")
}
