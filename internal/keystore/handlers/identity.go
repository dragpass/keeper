// identity.go — RSA keypair generation + public-key retrieval handlers.
// HandleGenerateKeypair / HandleGetPublicKey / HandleGetServerPublicKey —
// three actions routed by the dispatcher.
//
// The three signing handlers (HandleSignAlias / HandleSignAliasWithTimestamp /
// HandleSignChallengeToken) live in identity_sign.go.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGenerateKeypair handles keypair generation requests.
func HandleGenerateKeypair(d Deps, req proto.GenerateKeypairRequest) proto.BaseResponse {
	d.Logger.Println("keypair generation request processing...")

	// VerifyServerSig wraps PEM fetch + parse + base64 decode + RSA-PSS verify
	// (4 steps) into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "keypair generation"); !ok {
		return resp
	}

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("keypair generation error: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair generation failed: "+err.Error())
	}

	// Protect private key PEM in memguard, save to keystore, then destroy
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := keychain.SavePrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("private key save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "private key save failed: "+err.Error())
	}

	// Save the new public key to the keystore
	if err := keychain.SavePublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("public key save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "public key save failed: "+err.Error())
	}

	// Delete existing session code if exists
	if err := keychain.DeleteSessionCode(d.Store); err != nil {
		d.Logger.Printf("warning: failed to delete existing session code: %v", err)
	}

	d.Logger.Println("keypair generation and keypair save successful")
	return proto.BaseResponse{Success: true, Data: proto.GenerateKeypairResponseData{PublicKey: keyPair.PublicKey}}
}

// HandleGetPublicKey handles public key retrieval requests.
func HandleGetPublicKey(d Deps, req proto.GetPublicKeyRequest) proto.BaseResponse {
	d.Logger.Println("public key retrieval request processing...")
	publicKeyPEM, err := keychain.GetPublicKey(d.Store)
	if err != nil {
		d.Logger.Printf("public key retrieval error: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	d.Logger.Println("public key retrieval successful")
	return proto.BaseResponse{Success: true, Data: proto.GetPublicKeyResponseData{PublicKey: publicKeyPEM}}
}

// HandleGetServerPublicKey handles server public key retrieval requests.
func HandleGetServerPublicKey(d Deps, req proto.GetServerPublicKeyRequest) proto.BaseResponse {
	d.Logger.Println("server public key retrieval request processing...")
	serverPublicKeyPEM, err := keychain.GetServerPublicKey(d.Store)
	if err != nil {
		d.Logger.Printf("server public key retrieval error: %v", err)
		return errs.Response(err) // ErrSecretNotFound / ErrServerKeyVersionNotFound → not_found
	}
	d.Logger.Println("server public key retrieval successful")
	return proto.BaseResponse{Success: true, Data: proto.GetServerPublicKeyResponseData{PublicKey: serverPublicKeyPEM}}
}
