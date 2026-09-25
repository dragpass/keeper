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
	// For a room, room_name_plaintext_b64 is resealed for epoch 1 from the
	// pending create, and the response carries it as name_* for the server to
	// store with the Commit.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           members[1..32] { account_id, device_id, key_package_b64 },
	//           rotation_statements?, room_name_plaintext_b64? (1..256B),
	//           app_context_b64? (1..65536B, 0.0.55)
	//   Output: MLSCommitResponseData
	MLSGroupCreate = "mls_group_create"

	// MLSGroupDiscardUnaccepted drops this device's own group create that was
	// never accepted: the loser of two members opening the same DM at once.
	// It succeeds only when the pending Commit is the one named and is the
	// create (built against epoch 0) and the record was never confirmed past
	// epoch 0; then the group state and the pending Commit go, and mls_join can
	// take the winner's Welcome. Every other state is CHAT_STATE_CONFLICT and
	// writes nothing. Idempotent: with no group left it answers discarded
	// false. Call it only once the server has given the epoch to another
	// create: an accepted create whose answer was lost looks the same here.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id
	//   Output: { discarded, generation }
	MLSGroupDiscardUnaccepted = "mls_group_discard_unaccepted"

	// MLSConversationForgetRemoved drops the group state of a conversation
	// this device was removed from, so that a Welcome that adds it again is
	// joined into a clean record: a device takeover that was undone leaves
	// the old device's latch waiting for a key that will never appear (design
	// M4.4). It succeeds only when the last Commit applied to the confirmed
	// state removed this device's leaf; then the group state, the pending
	// Commit and both latches go, and the sealed local history stays
	// readable. Every other state is CHAT_STATE_CONFLICT and writes nothing.
	// Idempotent: with no group left it answers forgotten false.
	//
	//   Inputs: permit, org_id, conversation_id
	//   Output: { forgotten, generation }
	MLSConversationForgetRemoved = "mls_conversation_forget_removed"

	// MLSCommitBuild builds one pending Commit of exactly one kind against
	// expected_epoch: add, remove_account_ids (every leaf of each account),
	// replace (each account's leaves swapped for the leaf of the device that
	// took it over, under the key the permit names; design M4.4), or
	// update_self (a path update that also moves the group onto the device's
	// active leaf key after a rotation). A plan that mixes kinds is refused.
	//
	// For a room, room_name_plaintext_b64 — the name as this device last
	// opened it — is resealed for the epoch the Commit creates, computed from
	// the pending Commit before the CAS, and returned as name_* for the server
	// to store atomically with the Commit.
	//
	//   Inputs: permit, org_id, conversation_id, client_commit_id,
	//           expected_epoch (>=1), exactly one of add[1..32] /
	//           remove_account_ids[1..64] /
	//           replace[1..32] { account_id, key_package_b64 } /
	//           update_self, rotation_statements?,
	//           room_name_plaintext_b64? (1..256B),
	//           app_context_b64? (1..65536B, 0.0.55)
	//   Output: MLSCommitResponseData
	//
	// app_context_b64 is the app's own note of the Commit, kept with it and
	// returned by MLSConversationStatus until the verdict, so an app that
	// lost that note can still repost the Commit. A retry under the same id
	// keeps the first note. The name the first build sealed is reported by
	// MLSConversationStatus too.
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
	//
	// The plaintext is also sealed into the local history in the same write as
	// the outbox entry, keyed by client_message_id until MLSMarkSent gives it
	// the server's seq: mls-rs never opens a message from its own leaf, so that
	// copy is the only way this device reads what it sent.
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id,
	//           expected_epoch (>=1), plaintext_b64 (1..6144B, UTF-8)
	//   Output: { client_message_id, ciphertext_b64, epoch, leaf_index,
	//             content_type, generation, created }
	MLSEncrypt = "mls_encrypt"

	// MLSMarkSent binds the sealed copy of a message this device sent to the
	// seq POST /:id/messages returned. Idempotent on the same pair (bound:
	// false, nothing written). Refused with CHAT_STATE_CONFLICT when the seq
	// already carries another message's copy or the message is already bound
	// to another seq, and CHAT_STATE_NOT_FOUND when no copy for the id is left.
	//
	//   Inputs: permit, org_id, conversation_id, client_message_id, seq (>=1)
	//   Output: { client_message_id, seq, bound, generation }
	MLSMarkSent = "mls_mark_sent"

	// MLSDecryptBatchForAppDisplay opens a page of application messages for
	// the DragPass app's own screen, through chatstate.Store.ReceiveBatch and
	// the local history: a seq already delivered, or sent by this device and
	// bound by MLSMarkSent, is answered from the sealed copy with from_history
	// and no MLS key. The response is MLSDisplayResponseData, plaintext_b64
	// its only plaintext field (the chat carve-out, M6.3). All or nothing: one message that fails refuses the
	// batch with no plaintext and nothing written. The one exception is a
	// message this device sent that has no sealed copy here: it is reported as
	// state own_without_local_copy with an empty plaintext entry, and the rest
	// of the batch proceeds. On a conversation latched NeedsRekey a batch of
	// history hits only is still answered; one new message refuses the batch
	// with CHAT_STATE_REKEY_REQUIRED.
	//
	//   Inputs: permit, org_id, conversation_id,
	//           messages[1..200] { seq, ciphertext_b64 (1..8208B) }
	//   Output: { plaintext_b64[], items[] { seq, state, sender_account_id,
	//             sender_device_id, epoch, sender_leaf_index, content_type,
	//             generation, from_history } }
	MLSDecryptBatchForAppDisplay = "mls_decrypt_batch_for_app_display"

	// MLSRoomNameSeal seals a room's name under the confirmed epoch's MLS
	// exporter ("dragpass room name", context conversation_id, 32 bytes) with
	// AES-256-GCM, a random IV and AAD dragpass.room.name|1|<conversation_id>|
	// <epoch>. For a rename, and for the epoch 0 name a room is created with
	// while its create is pending. Writes nothing.
	//
	//   Inputs: permit, org_id, conversation_id, plaintext_b64 (1..256B, UTF-8)
	//   Output: { epoch, name_iv_b64, name_ciphertext_b64 }
	MLSRoomNameSeal = "mls_room_name_seal"

	// MLSRoomNameOpen opens a room's name for the DragPass app's own screen.
	// Only the confirmed epoch's name opens (CHAT_MLS_EPOCH_STALE otherwise):
	// an older epoch's exporter is gone. The response is
	// MLSDisplayResponseData with exactly one plaintext_b64 entry, the same
	// carve-out as the display batch rather than a new one. Writes nothing.
	//
	//   Inputs: permit, org_id, conversation_id, epoch, name_iv_b64 (12B),
	//           name_ciphertext_b64 (17..272B)
	//   Output: { plaintext_b64: [name] }
	MLSRoomNameOpen = "mls_room_name_open"

	// MLSConversationStatus reports this device's copy of the conversation:
	// the confirmed epoch, whether a Commit is pending and under which
	// client_commit_id, the accounts the S-1 latch would refuse a send for
	// right now, whether the record is latched NeedsRekey, and whether a group
	// exists at all. Read-only: it writes nothing of its own, and returns no
	// secret and nothing derived from one.
	//
	//   Inputs: permit, org_id, conversation_id
	//   Output: { epoch, has_group_state, commit_pending,
	//             pending_client_commit_id, pending_app_context_b64?,
	//             pending_name_epoch?, pending_name_iv_b64?,
	//             pending_name_ciphertext_b64?,
	//             removal_latch_account_ids, needs_rekey, rekey_cause?,
	//             removed_from_group }
	MLSConversationStatus = "mls_conversation_status"

	// MLSRejoinRequestSign signs this device's request to be re-seated in a
	// conversation whose every Welcome it could not use (0.0.55, design Q6).
	// permit-gated. Request: permit, org_id, conversation_id. Response:
	// request {conversation_id, account_id, device_id, signature_key_fp,
	// requested_at, signature}, the account key's signature over
	// dragpass.mls.rejoin|1|<conversation_id>|<account_id>|<device_id>|<signature_key_fp>|<requested_at>.
	MLSRejoinRequestSign = "mls_rejoin_request_sign"

	// MLSCommitAbandon drops a pending Commit built before 0.0.55 (no
	// app_context_b64) on the user's confirmation (0.0.55, design Q23).
	// permit-gated. Request: permit, org_id, conversation_id,
	// client_commit_id. Response: generation. A pending Commit that carries
	// an app context is CHAT_STATE_CONFLICT: it can be reposted.
	MLSCommitAbandon = "mls_commit_abandon"

	// MLSLeaveRequestSign signs this device's request to leave a conversation
	// (0.0.55, design Q13). permit-gated. Request: permit, org_id,
	// conversation_id. Response: statement {conversation_id, account_id,
	// requested_at, signature}, the account key's signature over
	// dragpass.chat.leave|1|<conversation_id>|<account_id>|<requested_at>.
	// Any remaining member's Keeper accepts a Remove of this account that
	// carries it.
	MLSLeaveRequestSign = "mls_leave_request_sign"

	// OrgMemberRemovalSign signs an org admin's statement that an account was
	// removed from the organization (0.0.55, design Q5 (b)). Request: org_id,
	// removed_account_id, admin_account_id (this device's account). Response:
	// statement {org_id, removed_account_id, admin_account_id, removed_at,
	// signature} over
	// dragpass.org.member.removal|1|<org_id>|<removed_account_id>|<admin_account_id>|<removed_at>.
	OrgMemberRemovalSign = "org_member_removal_sign"

	// MLSDeviceRevokeSign signs this account's revocation of one of its
	// devices' leaves (0.0.55, design Q13). Request: account_id (this
	// device's account), device_id. Response: statement {account_id,
	// device_id, revoked_at, signature} over
	// dragpass.mls.device.revoke|1|<account_id>|<device_id>|<revoked_at>.
	MLSDeviceRevokeSign = "mls_device_revoke_sign"
)
