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

type PingResponseData struct {
	Version      string `json:"version"`
	Hash         string `json:"hash"`
	Path         string `json:"path"`
	ChatContract int    `json:"chat_contract"`
}
