package localrpc

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// accountRoutes is the account key rotation and the device wipe the App runs
// from its settings, the same actions the Native Messaging path offers.
// The rotation's group DEK rewrap names no target: Keeper binds it to its own
// pending key, so the App cannot point a self-wrap at any other key.
var accountRoutes = map[string]appRoute{
	"/v1/account-key/rotate/status": {
		action: proto.ActionRotateUserKeypairStatus,
		input:  func() any { return &proto.RotateUserKeypairStatusRequest{} },
	},
	"/v1/account-key/rotate/abort": {
		action: proto.ActionRotateUserKeypairAbort,
		input:  func() any { return &proto.RotateUserKeypairAbortRequest{} },
	},
	"/v1/account-key/rotate/prepare": {
		action: proto.ActionRotateUserKeypairPrepare,
		input:  func() any { return &proto.RotateUserKeypairPrepareRequest{} },
	},
	"/v1/account-key/rotate/rewrap-group-dek": {
		action: proto.ActionDEKRewrapForMember,
		input:  func() any { return &appRotationRewrap{} },
		bind:   bindRotationRewrap,
	},
	"/v1/account-key/rotate/promote": {
		action: proto.ActionRotateUserKeypairPromote,
		input:  func() any { return &proto.RotateUserKeypairPromoteRequest{} },
	},
	// The Extension's "forget this device" deletes the device key and nothing
	// else: the device-wrapped personal DEK left behind cannot be opened
	// without it, and the next password login writes a new one.
	"/v1/device/forget": {
		input: func() any { return &proto.DeleteDeviceKeyRequest{} },
		run:   runDeviceForget,
	},
}

// runDeviceForget deletes the device key only when one is stored. The delete
// action refuses a missing key, and the App retries a forget whose server
// revocation failed after the local wipe went through. The check and the
// delete run as one unit, so no other caller's delete lands between them.
func runDeviceForget(s *Server, request appRequest, _ any) (proto.BaseResponse, error) {
	return s.handleSteps(request.token, request.epoch, func(step stepFunc) (proto.BaseResponse, error) {
		status, err := step(proto.ActionDeviceKeyStatus, nil)
		if err != nil || !status.Success {
			return status, err
		}
		var data proto.DeviceKeyStatusResponseData
		if err := remarshal(status.Data, &data); err != nil {
			return proto.BaseResponse{}, err
		}
		if data.Present {
			deleted, err := step(proto.ActionDeleteDeviceKey, nil)
			if err != nil || !deleted.Success {
				return deleted, err
			}
		}
		return proto.BaseResponse{Success: true, Data: map[string]bool{"forgotten": data.Present}}, nil
	})
}

type appRotationRewrap struct {
	WrappedForMeB64 string `json:"wrapped_for_me_b64"`
}

// bindRotationRewrap wraps to this Keeper's own pending key. A self-wrap is
// not a peer wrap, so no account ids travel and no pin applies, as on the
// Native Messaging path; without a pending key there is nothing to rewrap to.
func bindRotationRewrap(s *Server, input any) (any, error) {
	in := input.(*appRotationRewrap)
	pending, err := s.pendingPublicKey()
	if err != nil {
		return nil, err
	}
	return proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: in.WrappedForMeB64,
		OtherPublicKey:  pending,
	}, nil
}

func (s *Server) pendingPublicKey() (string, error) {
	response, err := s.handle("", proto.ActionRotateUserKeypairStatus, nil)
	if err != nil || !response.Success {
		return "", errAppRouteRefused
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return "", err
	}
	var data proto.RotateUserKeypairStatusResponseData
	if err := json.Unmarshal(encoded, &data); err != nil || !data.HasPending || data.PendingPublicKey == "" {
		return "", errAppRouteRefused
	}
	return data.PendingPublicKey, nil
}
