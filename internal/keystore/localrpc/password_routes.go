package localrpc

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// passwordRoutes is the master password change the App runs from its
// settings. It needs the DEK under the device key between its two actions,
// and that wrap never leaves Keeper, so Keeper composes the change itself.
var passwordRoutes = map[string]appRoute{
	"/v1/auth/password/rewrap": {
		input: func() any { return &appPasswordRewrap{} },
		run:   runPasswordRewrap,
	},
}

type appPasswordRewrap struct {
	Password        string `json:"password"`
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
	NewPassword     string `json:"new_password"`
}

// runPasswordRewrap opens the server's password-wrapped DEK with the current
// password, which is the check that the caller knows it, then wraps the same
// DEK under the new password. The device-wrapped DEK between the two steps
// stays in Keeper; only the new password wrap, which the server stores as
// is, is answered. A wrong current password is the first action's refusal.
// Both steps run as one unit, so no device key delete or rotation lands
// between the wrap the first step stores and the second step opening it.
func runPasswordRewrap(s *Server, request appRequest, input any) (proto.BaseResponse, error) {
	in := input.(*appPasswordRewrap)
	if in.NewPassword == "" {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	return s.handleSteps(request.token, request.epoch, func(step stepFunc) (proto.BaseResponse, error) {
		restore, err := json.Marshal(proto.DEKRotateToDeviceKeyRequest{
			Password:        in.Password,
			EncryptedDEKB64: in.EncryptedDEKB64,
		})
		if err != nil {
			return proto.BaseResponse{}, err
		}
		opened, err := step(proto.ActionDEKRotateToDeviceKey, restore)
		if err != nil || !opened.Success {
			return opened, err
		}
		var device proto.DEKRotateToDeviceKeyResponseData
		if err := remarshal(opened.Data, &device); err != nil || device.DeviceWrappedDEKB64 == "" {
			return proto.BaseResponse{}, errAppRouteRefused
		}
		rotate, err := json.Marshal(proto.DEKRotateToNewPasswordRequest{
			EncryptedDEKB64: device.DeviceWrappedDEKB64,
			NewPassword:     in.NewPassword,
		})
		if err != nil {
			return proto.BaseResponse{}, err
		}
		rotated, err := step(proto.ActionDEKRotateToNewPassword, rotate)
		if err != nil || !rotated.Success {
			return rotated, err
		}
		var wrapped proto.DEKRotateToNewPasswordResponseData
		if err := remarshal(rotated.Data, &wrapped); err != nil || wrapped.EncryptedDEKB64 == "" {
			return proto.BaseResponse{}, errAppRouteRefused
		}
		return proto.BaseResponse{Success: true, Data: map[string]string{
			"encrypted_dek_b64": wrapped.EncryptedDEKB64,
		}}, nil
	})
}
