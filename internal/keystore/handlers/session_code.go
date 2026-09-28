// session_code.go — SessionCode handlers.
// HandleSaveSessionCode / HandleGetSessionCode — two actions routed by the dispatcher.
// Right after signup/login, unwraps the server-issued SessionCode via RSA-OAEP, then saves + retrieves.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/awnumar/memguard"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandleSaveSessionCode handles session code save requests.
func HandleSaveSessionCode(d Deps, req proto.SaveSessionCodeRequest) proto.BaseResponse {
	d.Logger.Println("encrypted session code save request processing...")

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.EncryptedSessionCode, req.Signature, req.ServerKeyVersion, "session code save"); !ok {
		return resp
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedSessionCode)
	if err != nil {
		d.Logger.Printf("session code save error: failed to decode encrypted session code: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted session code: "+err.Error())
	}

	// The server encrypted the session code to the public key it now holds
	// for the account. Whichever local key opens it is the one the server
	// accepted, and only that keypair is promoted (keychain.AcceptSessionCode).
	accepted, sessionCode, err := keychain.AcceptSessionCode(d.Store, func(privateKeyPEM string) (string, bool) {
		keyBuf := memguard.NewBufferFromBytes([]byte(privateKeyPEM))
		defer keyBuf.Destroy()
		privateKey, err := parsePrivateKeyFromSecureBuf(keyBuf)
		if err != nil {
			return "", false
		}
		sessionBuf, err := decryptToSecureBuf(privateKey, encryptedBytes)
		if err != nil {
			return "", false
		}
		defer sessionBuf.Destroy()
		return string(sessionBuf.Bytes()), true
	})
	switch {
	case errors.Is(err, keychain.ErrSessionCodeUnopened):
		d.Logger.Println("session code save error: no local key opens the session code")
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to decrypt session code: no local key opens it")
	case err != nil:
		d.Logger.Printf("session code save error: %v", err)
		// ErrSecretNotFound → not_found; otherwise → storage failure.
		if errors.Is(err, keychain.ErrSecretNotFound) {
			return errs.Response(err)
		}
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "session code save failed: "+err.Error())
	}
	switch accepted {
	case keychain.SessionCodeAcceptedSignup:
		d.Logger.Println("pending keypair promoted to permanent storage (signup completed)")
	case keychain.SessionCodeAcceptedRecovery:
		d.Logger.Println("staged recovery keypair promoted (recovery completed)")
	default:
		d.Logger.Println("no pending keypair accepted (login on another device flow)")
	}

	d.Logger.Println("session code decryption and save successful")
	return proto.BaseResponse{Success: true, Data: proto.SaveSessionCodeResponseData{SessionCode: sessionCode, Promoted: string(accepted)}}
}

// HandleGetSessionCode handles session code retrieval requests.
func HandleGetSessionCode(d Deps, req proto.GetSessionCodeRequest) proto.BaseResponse {
	d.Logger.Println("session code retrieval request processing...")
	sessionCode, err := keychain.GetSessionCode(d.Store)
	if err != nil {
		d.Logger.Printf("session code retrieval error: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	return proto.BaseResponse{Success: true, Data: proto.GetSessionCodeResponseData{SessionCode: sessionCode}}
}
