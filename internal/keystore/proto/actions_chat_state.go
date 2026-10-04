// actions_chat_state.go — Wire-protocol Action* constants for DragPass chat
// v2's conversation state.
//
// Its own domain fragment: these actions are the only ones that touch the
// sealed chat state directory outside the MLS actions, and every one but the
// purge is gated on a conversation-state permit. Storage:
// internal/keystore/chatstate. Design: dragpass-control-plane
// docs/security/adr-ratchet-state-storage.md.
//
// The pre-MLS send and receive actions that consumed chain positions by hand
// (chat_state_reserve_send, chat_state_commit_outbox, chat_state_mark_received)
// are gone. mls_encrypt and the receive path now consume and mark positions
// themselves; an old client that still sends those names gets the
// dispatcher's unknown-action refusal.
//
// **Why the gated ones demand a server-signed permit.** The dispatcher has
// one action registry and the Keeper cannot tell who launched it — extension
// service worker, popup, `@dragpass/mcp`, or `dragpass-run` all speak the same
// protocol to the same binary. So "MCP does not call these" is a convention
// that survives exactly until someone adds a call, and a convention is not what
// should stand between a prompt injection and a conversation's chain state. A
// permit is issued on user-JWT routes only; the `/api/v1/mcp/*` service token
// cannot reach those routes, so an MCP process that frames these requests by
// hand still cannot produce one. What this does not stop is a local attacker
// who already holds a live user session — the same carve-out the account key
// trust contract states about pins, and stated the same way here.

package proto

const (
	// ChatStateReadOutbox returns the stored ciphertext for a client message
	// id. Everything it returns is public material the transport already
	// carries; the permit is required because the set of conversations this
	// device has state for is not.
	//
	// For an mls_encrypt entry it also names the leaf and the content type, so
	// an app that lost mls_encrypt's answer can post the stored bytes without
	// the plaintext (0.0.55).
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id
	//   Output: { epoch, chain_index, iv_b64, ciphertext_b64, leaf_index,
	//             content_type? }
	ChatStateReadOutbox = "chat_state_read_outbox"

	// ChatStatePurge erases one account's chat state: the sealed files, the
	// anchors, and the seal key. Logout calls it, because a logout knows whose
	// state is going away. A device reset does not name an account — it is
	// reached for once the server-side account is gone — so
	// reset_device_identity erases every owner's state in-process instead of
	// through this action. Unlike peer_key_pin, which survives a logout so a
	// human's out-of-band check is not thrown away, chat state must not: what
	// is left behind is an entrance for a rewound chain later.
	//
	// The one action here with no permit. It only deletes, and any local
	// process can already delete these files with the filesystem, so requiring
	// a server round trip would buy nothing and would make erasure fail exactly
	// when the user is logging out of a server they cannot reach.
	//
	//   Inputs: owner_account_id
	//   Output: { removed_conversations }
	ChatStatePurge = "chat_state_purge"
)
