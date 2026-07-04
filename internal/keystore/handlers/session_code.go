// session_code.go — SessionCode handlers.
// HandleSaveSessionCode / HandleGetSessionCode — two actions routed by the dispatcher.
// Right after signup/login, unwraps the server-issued SessionCode via RSA-OAEP, then saves + retrieves.

package handlers

import (
	"encoding/base64"

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

	// Try to promote pending keypair to permanent storage
	// This is safe for both signup and login-on-another-device flows:
	// - Signup: pending keypair exists, gets promoted ✅
	// - Login on another device: no pending keypair, nothing happens ✅
	promoted, err := keychain.PromotePendingKeypair(d.Store)
	if err != nil {
		d.Logger.Printf("session code save error: failed to promote pending keypair: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to promote pending keypair: "+err.Error())
	}
	if promoted {
		d.Logger.Println("pending keypair promoted to permanent storage (signup completed)")
	} else {
		d.Logger.Println("no pending keypair found (login on another device flow)")
	}

	// Get the Helper's private key from keystore into protected memory
	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("session code save error: failed to get private key: %v", err)
		// ErrSecretNotFound → not_found; otherwise → internal_error.
		return errs.Response(err)
	}
	defer privKeyBuf.Destroy()

	// Parse the private key from protected buffer
	privateKey, err := parsePrivateKeyFromSecureBuf(privKeyBuf)
	if err != nil {
		d.Logger.Printf("session code save error: failed to parse private key: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse private key: "+err.Error())
	}

	// Decode the encrypted session code from base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedSessionCode)
	if err != nil {
		d.Logger.Printf("session code save error: failed to decode encrypted session code: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted session code: "+err.Error())
	}

	// Decrypt the session code into protected memory
	sessionBuf, err := decryptToSecureBuf(privateKey, encryptedBytes)
	if err != nil {
		d.Logger.Printf("session code save error: failed to decrypt session code: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to decrypt session code: "+err.Error())
	}
	defer sessionBuf.Destroy()

	sessionCode := string(sessionBuf.Bytes())

	// Save the decrypted session code
	if err := keychain.SaveSessionCode(d.Store, sessionCode); err != nil {
		d.Logger.Printf("session code save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "session code save failed: "+err.Error())
	}

	d.Logger.Println("session code decryption and save successful")
	return proto.BaseResponse{Success: true, Data: proto.SaveSessionCodeResponseData{SessionCode: sessionCode}}
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
