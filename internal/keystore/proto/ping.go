// ping_models.go — Ping response payload.

package proto

type PingResponseData struct {
	Version string `json:"version"`
	Hash    string `json:"hash"`
	Path    string `json:"path"`
}
