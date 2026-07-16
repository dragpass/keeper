// actions.go — Wire-protocol Action* string constants.
//
// These constants are the `Action` field values in the Native Messaging
// request envelope and form part of the Extension(JS) ↔ Keeper(Go) wire
// protocol contract. The dispatcher's actionRegistry uses them as string
// keys to look up handlers.
//
// dispatcher.go and handler files under keystore root reference these via
// aliases (added in proto_aliases.go) by bare name (`ActionPing` etc.).
//
// The Action* set is domain-partitioned across sibling files; this file holds
// only the core / uncategorized actions:
//
//   actions_identity.go      — device / session / signup / login, keypair &
//                              device-key rotation, recovery, personal DEK,
//                              request-signing keys.
//   actions_server_keys.go   — server public-key trust anchor & multi-version
//                              server-key infrastructure.
//   actions_group_dek.go     — Group DEK / Item DEK ops, group sessions,
//                              decrypt-to-clipboard, guest transcrypt.
//   actions_archive.go       — per-org / per-account archive keypairs +
//                              break-glass re-grant.
//   actions_archive_quorum.go— archive-key admin quorum (Shamir N-of-M).

package proto

const (
	// Health check action
	ActionPing = "ping"

	// ClipboardGetLastHash: test-only — used by the Extension `pnpm e2e`
	// flow to verify that the dispatch path
	// (background → Keeper → Clipboard.Write) sent the correct plaintext.
	// Returns the SHA-256 hash recorded by MemoryClipboard + the write
	// count. In production OSClipboard this is rejected with
	// ErrCodeUnsupported — the action only returns a meaningful answer
	// in KEEPER_E2E_MODE.
	ActionClipboardGetLastHash = "clipboard_get_last_hash"
)
