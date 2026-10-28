package localrpc

import "github.com/dragpass/keeper/internal/keystore/proto"

// deviceIdentityRoutes give the App the Keeper's device id, the account
// binding it writes after a sign-in, the status the Extension also reads,
// and "sign out on this device" (0.0.58). None reads or answers key
// material, and each runs one action with its own strict request.
var deviceIdentityRoutes = map[string]appRoute{
	"/v1/account/chat-session/status":  {input: func() any { return &struct{}{} }, run: runChatLoginStatus},
	"/v1/account/chat-session/prepare": {input: func() any { return &chatLoginPrepare{} }, run: runChatLoginPrepare},
	"/v1/account/chat-session/commit":  {input: func() any { return &chatLoginCommit{} }, run: runChatLoginCommit},
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
	"/v1/account/binding/signout": {
		action: proto.ActionAccountBindingSignout,
		input:  func() any { return &proto.AccountBindingSignoutRequest{} },
	},
}

type chatLoginPrepare struct {
	AfterSequence uint64 `json:"after_sequence"`
	IntentID      string `json:"intent_id"`
	Predecessor   string `json:"predecessor_generation"`
}

type chatLoginCommit struct {
	IntentID  string `json:"intent_id"`
	AccountID string `json:"account_id"`
	Alias     string `json:"alias"`
}

func runChatLoginStatus(s *Server, _ appRequest, _ any) (proto.BaseResponse, error) {
	return s.app.ChatLoginStatus(), nil
}
func runChatLoginPrepare(s *Server, _ appRequest, input any) (proto.BaseResponse, error) {
	in := input.(*chatLoginPrepare)
	if !leaseIDPattern.MatchString(in.IntentID) || (in.Predecessor != "" && !leaseIDPattern.MatchString(in.Predecessor)) {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	return s.app.PrepareChatLogin(in.IntentID, in.Predecessor, in.AfterSequence), nil
}
func runChatLoginCommit(s *Server, _ appRequest, input any) (proto.BaseResponse, error) {
	in := input.(*chatLoginCommit)
	validation := proto.AccountBindingSetRequest{AccountID: in.AccountID, Alias: in.Alias}
	if !leaseIDPattern.MatchString(in.IntentID) || validation.Validate() != nil {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	return s.app.CommitChatLogin(in.IntentID, in.AccountID, in.Alias), nil
}
