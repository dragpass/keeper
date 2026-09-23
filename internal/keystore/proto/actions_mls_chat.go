// actions_mls_chat.go — Wire-protocol Action* constants for the MLS half of
// DragPass chat v2.
//
// These sit on top of the chat_state_* actions rather than beside them: the
// same sealed state directory, the same per-conversation lock, the same
// conversation-state permit (canonical v3), and one new thing — the MLS group
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
	// expected_epoch: add, remove_account_ids (every leaf of each account), or
	// update_self (a path update that also moves the group onto the device's
	// active leaf key after a rotation). A plan that mixes kinds is refused.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           expected_epoch (>=1), exactly one of add[1..32] /
	//           remove_account_ids[1..64] / update_self, rotation_statements?
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
	// group must be named by this conversation id.
	//
	//   Inputs: permit, org_id, conversation_id, welcome_b64,
	//           rotation_statements?
	//   Output: { epoch }
	MLSJoin = "mls_join"
)
