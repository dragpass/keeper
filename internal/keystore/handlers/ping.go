// ping.go — Health/version probe handler.
// HandlePing — action routed by the dispatcher. Echoes version/hash/path metadata.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/version"
)

// HandlePing handles ping requests.
func HandlePing(d Deps, req proto.PingRequest) proto.BaseResponse {
	d.Logger.Println("ping request processing...")
	return proto.BaseResponse{
		Success: true,
		Data: proto.PingResponseData{
			Version: version.Version,
			Hash:    version.BinaryHash,
			Path:    version.BinaryPath,
		},
	}
}
