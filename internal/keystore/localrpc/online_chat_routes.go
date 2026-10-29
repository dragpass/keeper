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

type onlineProcessInput struct {
	Request    proto.MLSProcessRequest `json:"request"`
	AppBinding string                  `json:"app_binding"`
	DeviceID   string                  `json:"device_id"`
}

type onlineProcessExecuteInput struct {
	onlineProcessInput
	Decision onlineauth.Decision `json:"decision"`
}

type onlineScopedRequest interface {
	Validate() error
	ChatStateContext() (proto.ChatStatePermit, string, string)
}

func onlineChatRefusal() proto.BaseResponse {
	return proto.BaseResponse{Error: "current online authorization required", ErrorCode: "online_revocation_check_required"}
}

func onlineChatIdentity(s *Server, request appRequest, scoped onlineScopedRequest, appBinding, deviceID string) (onlineauth.Identity, []byte, bool) {
	if scoped.Validate() != nil || appBinding == "" || !keychain.ValidDeviceID(deviceID) {
		return onlineauth.Identity{}, nil, false
	}
	permit, orgID, conversationID := scoped.ChatStateContext()
	login, err := keychain.ReadChatLogin(s.app.Store)
	if err != nil || login.Committing || login.Generation == "" || login.Generation != request.generation ||
		login.AccountID != permit.AccountID {
		return onlineauth.Identity{}, nil, false
	}
	encoded, err := json.Marshal(scoped)
	if err != nil {
		return onlineauth.Identity{}, nil, false
	}
	return onlineauth.Identity{
		AccountID: login.AccountID, DeviceID: deviceID,
		AppBinding:     appBinding,
		ConversationID: conversationID, OrgID: orgID,
		LocalSession: request.token, LoginGeneration: request.generation,
	}, encoded, true
}

func runOnlineChatPrepare(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineChatInput)
	identity, encoded, ok := onlineChatIdentity(s, request, input.Request, input.AppBinding, input.DeviceID)
	if !ok {
		return onlineChatRefusal(), nil
	}
	return onlineChatPrepare(s, proto.MLSDecryptBatchForAppDisplay, identity, encoded)
}

func onlineChatPrepare(s *Server, action string, identity onlineauth.Identity, encoded []byte) (proto.BaseResponse, error) {
	challenge, commitment, err := s.onlineChat.Prepare(action, encoded, identity)
	if err != nil {
		return onlineChatRefusal(), nil
	}
	return proto.BaseResponse{Success: true, Data: map[string]string{
		"challenge": challenge, "commitment": commitment,
	}}, nil
}

func runOnlineChatExecute(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineChatExecuteInput)
	return onlineChatExecute(s, request, proto.MLSDecryptBatchForAppDisplay,
		input.Request, input.AppBinding, input.DeviceID, input.Decision)
}

func onlineChatExecute(s *Server, request appRequest, action string, scoped onlineScopedRequest,
	appBinding, deviceID string, decision onlineauth.Decision) (proto.BaseResponse, error) {
	return s.handleFencedSteps(request, request.epoch, func(step stepFunc) (proto.BaseResponse, error) {
		identity, encoded, ok := onlineChatIdentity(s, request, scoped, appBinding, deviceID)
		if !ok || s.onlineChat.VerifyAndConsume(decision, action, encoded, identity) != nil {
			return onlineChatRefusal(), nil
		}
		return step(action, encoded)
	})
}

func runOnlineProcessPrepare(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineProcessInput)
	identity, encoded, ok := onlineChatIdentity(s, request, input.Request, input.AppBinding, input.DeviceID)
	if !ok {
		return onlineChatRefusal(), nil
	}
	return onlineChatPrepare(s, proto.MLSProcess, identity, encoded)
}

func runOnlineProcessExecute(s *Server, request appRequest, value any) (proto.BaseResponse, error) {
	input := value.(*onlineProcessExecuteInput)
	return onlineChatExecute(s, request, proto.MLSProcess,
		input.Request, input.AppBinding, input.DeviceID, input.Decision)
}
