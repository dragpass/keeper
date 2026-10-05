package localrpc

import "github.com/dragpass/keeper/internal/keystore/proto"

// deviceIdentityRoutes give the App the Keeper's device id, the account
// binding it writes after a sign-in, the status the Extension also reads,
// and "sign out on this device" (0.0.58). None reads or answers key
// material, and each runs one action with its own strict request.
var deviceIdentityRoutes = map[string]appRoute{
	"/v1/device/id": {
		action: proto.ActionDeviceIDEnsure,
		input:  func() any { return &proto.DeviceIDEnsureRequest{} },
	},
	"/v1/account/binding": {
		action: proto.ActionAccountBindingSet,
		input:  func() any { return &proto.AccountBindingSetRequest{} },
	},
	"/v1/device/status": {
		action: proto.ActionDeviceAccountStatus,
		input:  func() any { return &proto.DeviceAccountStatusRequest{} },
	},
	"/v1/device/signout": {
		action: proto.ActionDeviceSignout,
		input:  func() any { return &proto.DeviceSignoutRequest{} },
	},
}
