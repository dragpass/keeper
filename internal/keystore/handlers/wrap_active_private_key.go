// wrap_active_private_key.go — Recovery key re-issue handler.
//
// The Recovery flow (challenge-sign with old Keeper PEM / new keypair
// generation) lives in recovery.go. This handler is called when the user is
// already authenticated and only RK24 needs reissuing — the keypair itself is
// unchanged, only the wrap key is swapped.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleWrapActivePrivateKey — Recovery key re-issue.
//
// Flow:
//  1. decode wrap_key (AES-GCM 32B raw Base64) + length validation.
//  2. move Keychain active privkey PEM into memguard, wipe the original string.
//  3. AES-GCM(wrap_key, pem) → return wrapped Base64.
//  4. discard plaintext PEM by destroying the memguard buffer.
//
// The caller (Extension background) passes the wrapped Base64 to the server's
// /account/recovery-key/reissue and displays it to the user with the new RK24.
func HandleWrapActivePrivateKey(d Deps, req proto.WrapActivePrivateKeyRequest) proto.BaseResponse {
	d.Logger.Println("wrap active private key request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// decode wrap_key (AES-GCM 32B raw)
	wrapKey, resp, ok := decodeBase64Len(req.WrapKeyB64, 32, "wrap_key")
	if !ok {
		d.Logger.Printf("wrap active private key error: %s", resp.Error)
		return resp
	}
	defer secure.Zeroize(wrapKey)

	// Fetch current active privkey PEM. If not present in Keychain → 401-ish (user not registered).
	pemStr, err := keychain.GetPrivateKey(d.Store)
	if err != nil {
		d.Logger.Printf("wrap active private key error: keychain lookup: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure,
			"active private key not found in keychain: "+err.Error())
	}
	if pemStr == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound,
			"active private key empty in keychain")
	}

	// Move into memguard and wipe the original string — minimize the time the plaintext PEM lives on the heap.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)
	defer privKeyBuf.Destroy()

	wrappedB64, err := crypto.AESGCMEncryptBase64(wrapKey, privKeyBuf.Bytes())
	if err != nil {
		d.Logger.Printf("wrap active private key error: AES-GCM wrap failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure,
			"AES-GCM wrap failed: "+err.Error())
	}

	d.Logger.Println("wrap active private key: wrapped successfully")
	return proto.BaseResponse{Success: true, Data: proto.WrapActivePrivateKeyResponseData{
		WrappedKeeperB64: wrappedB64,
	}}
}
