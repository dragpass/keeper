package proto

import "github.com/dragpass/keeper/internal/keystore/onlineauth"

type GroupOnlinePrepareRequest struct {
	TokenID string                         `json:"token_id"`
	Request GroupDecryptToClipboardRequest `json:"request"`
}

func (r GroupOnlinePrepareRequest) Validate() error {
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	return r.Request.Validate()
}

type GroupOnlineExecuteRequest struct {
	TokenID  string                         `json:"token_id"`
	Request  GroupDecryptToClipboardRequest `json:"request"`
	Decision onlineauth.GroupDecision       `json:"decision"`
}

func (r GroupOnlineExecuteRequest) Validate() error {
	if err := requireMessageUUID(r.TokenID, "token_id"); err != nil {
		return err
	}
	return r.Request.Validate()
}
