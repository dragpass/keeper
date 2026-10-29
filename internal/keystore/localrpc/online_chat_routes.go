package localrpc

import (
	"encoding/json"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/onlineauth"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type onlineChatInput struct {
	Request    proto.MLSDecryptBatchForAppDisplayRequest `json:"request"`
	AppBinding string                                    `json:"app_binding"`
	DeviceID   string                                    `json:"device_id"`
}

type onlineChatExecuteInput struct {
	onlineChatInput
	Decision onlineauth.Decision `json:"decision"`
}

func onlineChatRefusal() proto.BaseResponse {
	return proto.BaseResponse{Error: "current online authorization required", ErrorCode: "online_revocation_check_required"}
}

func onlineChatIdentity(s *Server, request appRequest, input onlineChatInput) (onlineauth.Identity, []byte, bool) {
	if input.Request.Validate() != nil || input.AppBinding == "" || !keychain.ValidDeviceID(input.DeviceID) {
		return onlineauth.Identity{}, nil, false
	}
	login, err := keychain.ReadChatLogin(s.app.Store)
	if err != nil || login.Committing || login.Generation == "" || login.Generation != request.generation ||
		login.AccountID != input.Request.Permit.AccountID {
		return onlineauth.Identity{}, nil, false
	}
	encoded, err := json.Marshal(input.Request)
	if err != nil {
		return onlineauth.Identity{}, nil, false
	}
	return onlineauth.Identity{
		AccountID: login.AccountID, DeviceID: input.DeviceID,
		AppBinding:     input.AppBinding,
		ConversationID: input.Request.ConversationID, OrgID: input.Request.OrgID,
		LocalSession: request.token, LoginGeneration: request.generation,
	}, encoded, true
}

func runOnlineChatPrepare(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineChatInput)
	identity, encoded, ok := onlineChatIdentity(s, request, *input)
	if !ok {
		return onlineChatRefusal(), nil
	}
	challenge, commitment, err := s.onlineChat.Prepare(proto.MLSDecryptBatchForAppDisplay, encoded, identity)
	if err != nil {
		return onlineChatRefusal(), nil
	}
	return proto.BaseResponse{Success: true, Data: map[string]string{
		"challenge": challenge, "commitment": commitment,
	}}, nil
}

func runOnlineChatExecute(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineChatExecuteInput)
	return s.handleFencedSteps(request, request.epoch, func(step stepFunc) (proto.BaseResponse, error) {
		identity, encoded, ok := onlineChatIdentity(s, request, input.onlineChatInput)
		if !ok || s.onlineChat.VerifyAndConsume(input.Decision, proto.MLSDecryptBatchForAppDisplay, encoded, identity) != nil {
			return onlineChatRefusal(), nil
		}
		return step(proto.MLSDecryptBatchForAppDisplay, encoded)
	})
}
