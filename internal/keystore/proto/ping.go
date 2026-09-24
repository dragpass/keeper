// ping_models.go — Ping response payload.

package proto

// ChatContract names the chat request and response contract this build
// speaks, so the extension can tell two builds apart that report the same
// version string. 5 is the wave 5 contract: room roles in the group context,
// signed removal / leave / revoke statements and leaf handovers carried in the
// Commit, the takeover and recovery rules, the key package pool sweep. The MLS
// actions decode requests leniently (unknown fields are dropped), so a build
// without it would silently ignore the fields that contract adds; the
// extension refuses chat with a build that does not report at least the value
// it needs.
const ChatContract = 5

// ChatCapabilities names what this build's chat actions do, so a caller can
// require exactly what it depends on instead of reading anything into a number.
// Like chat_contract it is a compatibility signal and proves nothing: every
// request is still validated, and every signature still verified, on its own.
var ChatCapabilities = []string{
	"permit.v5",        // chat state permit canonical 5 (pending_device_revocations)
	"roles.v1",         // room roles in the group context (0xF0D1)
	"statements.v1",    // signed org removal / leave / device revoke, 30-day window
	"handover.v1",      // leaf handover approval for a device takeover
	"recovery.v1",      // a recovered identity is seated only by owner / admin / DM peer
	"pool_sweep.v1",    // mls_key_package_pool_sweep
	"sync_block.v1",    // a refused received Commit blocks the row, not the conversation
	"safety_number.v1", // pairwise safety number on peer_key_pin_verify
}

type PingResponseData struct {
	Version          string   `json:"version"`
	Hash             string   `json:"hash"`
	Path             string   `json:"path"`
	ChatContract     int      `json:"chat_contract"`
	ChatCapabilities []string `json:"chat_capabilities"`
}
