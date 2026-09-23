// actions_mls_chat.go — Wire-protocol Action* constants for the MLS half of
// DragPass chat v2.
//
// These sit on top of the chat_state_* actions rather than beside them: the
// same sealed state directory, the same per-conversation lock, the same
// conversation-state permit (canonical v4), and one new thing — the MLS group
// state inside the record is now read and written, by the Keeper only. No
// action here carries the group state, a secret, or a key across IPC in either
// direction. Storage: internal/keystore/chatstate. MLS: internal/keystore/mls.
// Design: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §7 and §12.2.
//
// **Every one of them is all or nothing.** A refusal — permit, validation,
// §5.3, MLS, storage — persists nothing: no group state, no pending Commit, no
// pin, no newest-declaration record, no pool deletion.
//
// **None of them is on the MCP surface**, for the reason actions_chat_state.go
// gives: the permit is issued on user-JWT routes only, and the MCP guard test in
// dispatch pins the set a tool call can reach.

package proto

const (
	// MLSGroupCreate creates the conversation's group at epoch 0, verifies
	// each initial member's KeyPackage (§5.3, plus the credential naming the
	// account and device the caller asked for), and builds the Add. The Add is
	// pending (§7.3): post it to the CAS endpoint, then report the verdict
	// through MLSCommitConfirm. Idempotent on client_commit_id.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           members[1..32] { account_id, device_id, key_package_b64 },
	//           rotation_statements?
	//   Output: MLSCommitResponseData
	MLSGroupCreate = "mls_group_create"

	// MLSCommitBuild builds one pending Commit of exactly one kind against
	// expected_epoch: add, remove_account_ids (every leaf of each account),
	// replace (each account's leaves swapped for the leaf of the device that
	// took it over, under the key the permit names; design M4.4), or
	// update_self (a path update that also moves the group onto the device's
	// active leaf key after a rotation). A plan that mixes kinds is refused.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           expected_epoch (>=1), exactly one of add[1..32] /
	//           remove_account_ids[1..64] /
	//           replace[1..32] { account_id, key_package_b64 } /
	//           update_self, rotation_statements?
	//   Output: MLSCommitResponseData
	MLSCommitBuild = "mls_commit_build"

	// MLSCommitConfirm settles the pending Commit with the server's CAS
	// verdict: accepted (the pending becomes the epoch), superseded with the
	// winner's Commit (the fork is dropped and the winner applied, verified),
	// or unknown (nothing moves; the Commit to repost comes back).
	// welcome_releasable is true only on accepted, and only for an Add.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           outcome ('accepted' | 'superseded' | 'unknown'),
	//           winner_commit_b64 (superseded only), rotation_statements?
	//   Output: MLSCommitConfirmResponseData
	MLSCommitConfirm = "mls_commit_confirm"

	// MLSProcess applies one row of GET /:id/mls/handshake — somebody else's
	// Commit — verifying every leaf it brings in. Rows apply in epoch order: a
	// row whose epoch is not the one after the confirmed epoch is refused with
	// CHAT_MLS_EPOCH_STALE, whether it was already applied or comes after one
	// that was not.
	//
	//   Inputs: permit, org_id, conversation_id, seq, epoch (the row's),
	//           commit_b64, rotation_statements?
	//   Output: { seq, epoch, removed, generation }
	MLSProcess = "mls_process"

	// MLSJoin joins the conversation's group from a Welcome addressed to one
	// of this device's KeyPackages, verifying every leaf of the tree. The
	// group must be named by this conversation id. A Welcome whose KeyPackage
	// this device no longer holds is CHAT_MLS_WELCOME_UNUSABLE.
	//
	//   Inputs: permit, org_id, conversation_id, welcome_b64,
	//           rotation_statements?
	//   Output: { epoch }
	MLSJoin = "mls_join"

	// MLSEncrypt encrypts one application message. Reserving the position,
	// encrypting at it and persisting the ciphertext are one locked section
	// (§7.2.1 T-c), through chatstate.Store.Send: two calls — reserve, then
	// encrypt — would let another process encrypt from the same group state
	// in between. Idempotent on client_message_id. Refused with
	// CHAT_MLS_ROTATION_PENDING while the S-1 latch holds, and with
	// CHAT_MLS_LEAF_REPLACEMENT_PENDING while the M4.4 latch holds, before any
	// position is consumed.
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id,
	//           expected_epoch (>=1), plaintext_b64 (1..6144B, UTF-8)
	//   Output: { client_message_id, ciphertext_b64, epoch, leaf_index,
	//             content_type, generation, created }
	MLSEncrypt = "mls_encrypt"

	// MLSDecryptBatchForAppDisplay opens a page of application messages for
	// the DragPass app's own screen, through chatstate.Store.ReceiveBatch and
	// the local history: a seq already delivered is answered from the sealed
	// copy with from_history and no MLS key. It widens the v1 reveal's
	// carve-out rather than adding one (M6.3): the response is
	// ConversationDecryptBatchForAppDisplayResponseData, plaintext_b64 its only
	// plaintext field. All or nothing: one message that fails refuses the
	// batch with no plaintext and nothing written. On a conversation latched
	// NeedsRekey a batch of history hits only is still answered; one new
	// message refuses the batch with CHAT_STATE_REKEY_REQUIRED.
	//
	//   Inputs: permit, org_id, conversation_id,
	//           messages[1..200] { seq, ciphertext_b64 (1..8208B) }
	//   Output: { plaintext_b64[], items[] { seq, sender_account_id,
	//             sender_device_id, epoch, sender_leaf_index, content_type,
	//             generation, from_history } }
	MLSDecryptBatchForAppDisplay = "mls_decrypt_batch_for_app_display"

	// MLSConversationStatus reports this device's copy of the conversation:
	// the confirmed epoch, whether a Commit is pending and under which
	// client_commit_id, the accounts the S-1 latch would refuse a send for
	// right now, whether the record is latched NeedsRekey, and whether a group
	// exists at all. Read-only: it writes nothing of its own, and returns no
	// secret and nothing derived from one.
	//
	//   Inputs: permit, org_id, conversation_id
	//   Output: { epoch, has_group_state, commit_pending,
	//             pending_client_commit_id, removal_latch_account_ids,
	//             needs_rekey }
	MLSConversationStatus = "mls_conversation_status"
)
