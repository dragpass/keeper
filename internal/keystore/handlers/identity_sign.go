// identity_sign.go — three handlers that sign data with the Keeper RSA private key.
//
//   HandleSignAlias              signup flow (pending keypair + Recovery wrap)
//   HandleSignAliasWithTimestamp login flow (alias:timestamp signing)
//   HandleSignChallengeToken     login flow (signs server challenge, verifies server-sig)
//
// Keypair generation / public-key retrieval (HandleGenerateKeypair /
// HandleGetPublicKey / HandleGetServerPublicKey) live in identity.go.

package handlers

import (
	"encoding/base64"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleSignAlias handles alias signing requests (signup flow).
//
// If req.WrapKeyB64 is provided, the Keeper internally wraps the pending
// private key with wrap_key (AES-GCM 32B raw) on the spot and returns the
// result in the response's wrapped_keeper field. The Extension never sees the
// plaintext private key PEM. Used for Recovery Key setup.
func HandleSignAlias(d Deps, req proto.SignAliasRequest) proto.BaseResponse {
	d.Logger.Println("alias signing request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Validate wrap_key_b64 if provided (early rejection to avoid wasted work)
	var wrapKey []byte
	if req.WrapKeyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.WrapKeyB64)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode wrap_key_b64: "+err.Error())
		}
		if len(decoded) != 32 {
			return errs.CodeResponse(errs.ErrCodeValidation, "wrap_key_b64 must be 32 bytes")
		}
		wrapKey = decoded
		defer secure.Zeroize(wrapKey)
	}

	_, keyErr := keychain.GetPrivateKey(d.Store)
	_, sessionErr := keychain.GetSessionCode(d.Store)

	// keypair + session code already exist
	if keyErr == nil && sessionErr == nil {
		d.Logger.Println("alias signing error: device already registered and session code exists")
		return errs.CodeResponse(errs.ErrCodeValidation, "device already registered. this device has already been registered for signup")
	}

	// keypair exists but session code is missing
	if keyErr == nil && sessionErr != nil {
		d.Logger.Println("alias signing error: orphaned keypair detected without session")
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair exists without session. please contact support or use account recovery")
	}

	d.Logger.Println("generating new keypair for signup...")
	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("keypair generation error: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair generation failed: "+err.Error())
	}

	// Save the new keypair to PENDING storage (not active yet)
	// This will be promoted to active status upon successful session code save
	if err := keychain.SavePendingPrivateKey(d.Store, keyPair.PrivateKey); err != nil {
		d.Logger.Printf("pending private key save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending private key save failed: "+err.Error())
	}

	if err := keychain.SavePendingPublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("pending public key save error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "pending public key save failed: "+err.Error())
	}
	d.Logger.Println("pending keypair generated and saved for signup (awaiting confirmation)")

	// Get the pending private key into protected memory
	pendingPrivBuf, err := getPendingPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("alias signing error: failed to get pending private key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer pendingPrivBuf.Destroy()

	// Sign the alias using the pending private key (from protected memory)
	signatureBase64, err := signDataSecure(pendingPrivBuf, req.Alias)
	if err != nil {
		d.Logger.Printf("alias signing error: failed to sign alias: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to sign alias: "+err.Error())
	}

	// If wrap_key is provided, AES-GCM-wrap the pending private key.
	var wrappedKeeper string
	if wrapKey != nil {
		wrappedKeeper, err = crypto.AESGCMEncryptBase64(wrapKey, pendingPrivBuf.Bytes())
		if err != nil {
			d.Logger.Printf("alias signing error: wrap pending private key failed: %v", err)
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrap pending private key failed: "+err.Error())
		}
		d.Logger.Println("pending private key wrapped with recovery wrap_key")
	}

	// Get the pending public key
	publicKeyPEM, err := keychain.GetPendingPublicKey(d.Store)
	if err != nil {
		d.Logger.Printf("alias signing error: failed to get pending public key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}

	d.Logger.Println("alias signing successful with pending keypair")
	return proto.BaseResponse{Success: true, Data: proto.SignAliasResponseData{
		Signature:     signatureBase64,
		PublicKey:     publicKeyPEM,
		WrappedKeeper: wrappedKeeper,
	}}
}

// HandleSignAliasWithTimestamp handles alias with timestamp signing requests (login flow).
func HandleSignAliasWithTimestamp(d Deps, req proto.SignAliasWithTimestampRequest) proto.BaseResponse {
	d.Logger.Println("alias with timestamp signing request processing...")

	// Generate current timestamp via injected Clock — d.Now() falls back to
	// time.Now when Deps.Clock is unset (production wiring).
	timestamp := d.Now().Unix()

	// Get the Helper's private key into protected memory
	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("alias signing error: keypair not found. device not registered: %v", err)
		return errs.CodeResponse(errs.ErrCodeNotFound, "device not registered. please complete signup first")
	}
	defer privKeyBuf.Destroy()

	// Create payload: Alias + ":" + Timestamp (matching server format)
	payload := fmt.Sprintf("%s:%d", req.Alias, timestamp)

	// Sign the payload using the Helper's private key (from protected memory)
	signatureBase64, err := signDataSecure(privKeyBuf, payload)
	if err != nil {
		d.Logger.Printf("alias signing error: failed to sign alias with timestamp: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to sign alias with timestamp: "+err.Error())
	}

	d.Logger.Println("alias with timestamp signing successful")
	return proto.BaseResponse{Success: true, Data: proto.SignAliasWithTimestampResponseData{Signature: signatureBase64, Timestamp: timestamp}}
}

// HandleSignChallengeToken handles challenge token signing requests.
func HandleSignChallengeToken(d Deps, req proto.SignChallengeTokenRequest) proto.BaseResponse {
	d.Logger.Println("challenge token signing request processing...")

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "challenge token signing"); !ok {
		return resp
	}

	// Get the Helper's private key into protected memory
	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("challenge token signing error: failed to get private key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer privKeyBuf.Destroy()

	// Sign the challenge token using Helper's private key (from protected memory)
	challengeSignatureBase64, err := signDataSecure(privKeyBuf, req.ChallengeToken)
	if err != nil {
		d.Logger.Printf("challenge token signing error: failed to sign challenge token: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to sign challenge token: "+err.Error())
	}

	d.Logger.Println("challenge token signing successful")
	return proto.BaseResponse{Success: true, Data: proto.SignChallengeTokenResponseData{Signature: challengeSignatureBase64}}
}
