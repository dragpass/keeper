// message_seal.go — HandleMessageSeal, the App's Secure Message seal.

package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleMessageSeal seals a Secure Message under the message AAD it builds
// from the request's fields, the AAD the display action rebuilds to open it.
func HandleMessageSeal(d Deps, req proto.MessageSealRequest) proto.BaseResponse {
	d.Logger.Println("message seal request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	plaintext, resp, ok := decodeBase64(req.PlaintextB64, "plaintext_b64")
	if !ok {
		return resp
	}
	defer secure.Zeroize(plaintext)
	aad := []byte(proto.MessageAADCanonical(
		req.OrgID, req.GroupID, req.DekVersion, proto.MessageSchemaVersion, req.TokenExpiresAt,
	))
	var iv, ciphertext []byte
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		var err error
		iv, ciphertext, err = crypto.SealAESGCM(d.Random(), groupDEK, plaintext, aad)
		return err
	})
	if useErr != nil {
		return sessionUseError(useErr, "message seal")
	}
	d.Logger.Println("message seal successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}
