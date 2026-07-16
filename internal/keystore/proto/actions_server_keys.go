// actions_server_keys.go — Wire-protocol Action* constants for the server
// public-key trust anchor and multi-version server-key infrastructure.
//
// Split out of actions.go for domain locality. Pure move — see actions.go for
// the wire-protocol contract note. Constant names / string values are
// unchanged.

package proto

const (
	// GetServerPublicKey returns the locally stored server public key
	// (account-independent trust anchor).
	ActionGetServerPublicKey = "getserverpubkey"

	// Server multi-version public-key infrastructure.
	//
	// RefreshServerKeys: Extension forwards the server's
	// `GET /api/v1/system/server-keys` response as-is. The Keeper (with
	// Root pubkey embedded) verifies the Root signature, then bulk-updates
	// the multi-version slots in the Keychain. Includes fingerprint TOFU
	// pinning. Intended to be called by the Extension on a chrome.alarms
	// 24h schedule.
	ActionRefreshServerKeys = "refresh_server_keys"
)
