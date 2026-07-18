package handlers

import "github.com/dragpass/keeper/internal/keystore/proto"

func HandleUserPresenceCapabilities(d Deps, _ proto.UserPresenceCapabilitiesRequest) proto.BaseResponse {
	capabilities := d.UserPresence.Capabilities()
	return proto.BaseResponse{
		Success: true,
		Data: proto.UserPresenceCapabilitiesResponseData{
			Available:       capabilities.Available,
			PromptSecret:    capabilities.PromptSecret,
			PromptNewSecret: capabilities.PromptNewSecret,
			Confirm:         capabilities.Confirm,
			ShowRecoveryKey: capabilities.ShowRecoveryKey,
			Backend:         capabilities.Backend,
		},
	}
}
