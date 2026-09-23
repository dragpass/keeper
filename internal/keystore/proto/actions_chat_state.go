// actions_chat_state.go — Wire-protocol Action* constants for DragPass chat
// v2's conversation state.
//
// Its own domain fragment, like actions_conversation.go, and for the same kind
// of reason: these five actions are the only ones that touch the sealed chat
// state directory, they are the only ones gated on a conversation-state permit,
// and none of them exists to move a payload — they exist to make sure a chain
// position is consumed exactly once. Storage: internal/keystore/chatstate.
// Design: dragpass-control-plane docs/security/adr-ratchet-state-storage.md.
//
// **What MLS will add and what is here now.** The state file already holds the
// opaque group-state blob, but nothing on the wire reads or writes it, and
// nothing here encrypts. These actions are the durability and mutual-exclusion
// layer the ratchet will sit on. That is deliberate: getting "who writes what,
// when" wrong breaks forward secrecy no matter which library lands on top.
//
// **Why every one of them demands a server-signed permit.** The dispatcher has
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
	// ChatStateReserveSend consumes chain positions for sending and returns
	// them. The consumption is on disk and fsynced before the response leaves,
	// which is the whole point: if this process dies between the answer and the
	// encryption, the message is lost and the position stays spent. The other
	// order would let the next send encrypt a different plaintext under the same
	// (key, nonce), and that is the one failure in this design that cannot be
	// undone once the ciphertext is out.
	//
	//   Inputs: permit, org_id, conversation_id, count (1..64)
	//   Output: { epoch, first_chain_index, count, generation }
	ChatStateReserveSend = "chat_state_reserve_send"

	// ChatStateCommitOutbox stores the ciphertext built for a reserved position
	// so a retransmission is a retransmission. Idempotent on
	// `client_message_id`: a second call returns what is already stored and
	// writes nothing, so a lost response cannot turn into a second encryption
	// at a second position. A position that was never reserved, or one that
	// already carries a different message, is refused.
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id, epoch,
	//           chain_index, iv_b64 (12B), ciphertext_b64 (17..8208B)
	//   Output: { stored (false = an entry already existed), epoch,
	//             chain_index, iv_b64, ciphertext_b64 }
	ChatStateCommitOutbox = "chat_state_commit_outbox"

	// ChatStateReadOutbox returns the stored ciphertext for a client message
	// id. Everything it returns is public material the transport already
	// carries; the permit is required because the set of conversations this
	// device has state for is not.
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id
	//   Output: { epoch, chain_index, iv_b64, ciphertext_b64 }
	ChatStateReadOutbox = "chat_state_read_outbox"

	// ChatStateMarkReceived records an inbound position and says whether this
	// delivery was the first. Persisted before the answer, for the mirror of
	// the reason ChatStateReserveSend persists first: a redelivery must advance
	// the state once, not twice, and a key that forward secrecy says is gone
	// must not come back because a crash replayed its deletion.
	//
	// The position takes four slots because MLS gives every sender its own
	// sender ratchet (RFC 9420 §9.1) and two of them each (§6.3.1): on (epoch,
	// generation) alone, two members' first messages of an epoch would each
	// look like a redelivery of the other.
	//
	//   Inputs: permit, org_id, conversation_id, epoch, sender_leaf_index,
	//           content_type ("handshake" | "application"), generation
	//   Output: { first_delivery, generation }
	ChatStateMarkReceived = "chat_state_mark_received"

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
