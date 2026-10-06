package localrpc

import "github.com/dragpass/keeper/internal/keystore/proto"

// authLoginRoutes are the sign-in, signup and recovery key steps. Each is its
// action's own request; the two that store a secret answer only that it was
// stored.
var authLoginRoutes = map[string]appRoute{
	"/v1/auth/login/sign-alias": {
		action: proto.ActionSignAliasWithTimestamp,
		input:  func() any { return &proto.SignAliasWithTimestampRequest{} },
	},
	"/v1/auth/login/sign-challenge": {
		action: proto.ActionSignChallengeToken,
		input:  func() any { return &proto.SignChallengeTokenRequest{} },
	},
	"/v1/auth/login/pending/sign-alias": {
		action: proto.ActionAuthLoginPendingSignAlias,
		input:  func() any { return &proto.AuthLoginPendingSignAliasRequest{} },
	},
	"/v1/auth/login/pending/sign-challenge": {
		action: proto.ActionAuthLoginPendingSignChallenge,
		input:  func() any { return &proto.AuthLoginPendingSignChallengeRequest{} },
	},
	"/v1/auth/login/restore-device-master": {
		action: proto.ActionDEKRotateToDeviceKey,
		input:  func() any { return &proto.DEKRotateToDeviceKeyRequest{} },
		shape:  answerStored,
	},
	"/v1/auth/login/ensure-request-key": {
		action: proto.ActionRequestKeyGenerate,
		input:  func() any { return &proto.RequestKeyGenerateRequest{} },
	},
	"/v1/auth/signup/prepare": {
		action: proto.ActionAuthSignupPrepare,
		input:  func() any { return &proto.AuthSignupPrepareRequest{} },
	},
	"/v1/auth/recovery-key/reissue-prepare": {
		action: proto.ActionAuthRecoveryReissuePrepare,
		input:  func() any { return &proto.AuthRecoveryReissuePrepareRequest{} },
	},
	"/v1/auth/signup/save-session-code": {
		action: proto.ActionSaveSessionCode,
		input:  func() any { return &proto.SaveSessionCodeRequest{} },
		shape:  answerSessionCodeStored,
	},
}

// answerStored keeps the device-wrapped DEK in Keeper.
func answerStored(any) any {
	return map[string]bool{"stored": true}
}

// answerSessionCodeStored keeps the session code in Keeper. Which stage a save
// promoted is not secret, and the App needs it to tell a recovery (grants to
// re-share) from a signup.
func answerSessionCodeStored(data any) any {
	if saved, ok := data.(proto.SaveSessionCodeResponseData); ok {
		return map[string]any{"stored": true, "promoted": saved.Promoted}
	}
	return answerStored(data)
}
