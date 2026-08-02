// Signup generates one DEK and wraps it for both password and device custody.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleDEKGenerateAndWrapDual performs the signup flow's dual wrap in one call.
func HandleDEKGenerateAndWrapDual(d Deps, req proto.DEKGenerateAndWrapDualRequest) proto.BaseResponse {
	d.Logger.Println("dek generate and wrap dual request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// protect password
	password := req.Password
	pwBuf := memguard.NewBufferFromBytes([]byte(password))
	secure.WipeString(&password)
	secure.WipeString(&req.Password)
	defer pwBuf.Destroy()

	data, response := generateAndWrapDual(d, pwBuf)
	if !response.Success {
		return response
	}
	d.Logger.Println("dek generate and wrap dual successful")
	return proto.BaseResponse{Success: true, Data: data}
}

func generateAndWrapDual(d Deps, password *memguard.LockedBuffer) (proto.DEKGenerateAndWrapDualResponseData, proto.BaseResponse) {
	var empty proto.DEKGenerateAndWrapDualResponseData

	// fetch deviceKey internally — never accept it via the IPC payload
	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return empty, errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	// generate salt + DEK
	salt := make([]byte, dekSaltLength)
	if err := d.FillRandom(salt); err != nil {
		return empty, errs.CodeResponse(errs.ErrCodeInternal, "failed to generate salt: "+err.Error())
	}
	dek := make([]byte, 32)
	if err := d.FillRandom(dek); err != nil {
		return empty, errs.CodeResponse(errs.ErrCodeInternal, "failed to generate dek: "+err.Error())
	}
	defer secure.Zeroize(dek)

	// password wrap
	kek := pbkdf2.Key(password.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)
	pwIV, pwCT, err := aesGCMSealSplit(kek, dek)
	if err != nil {
		return empty, errs.CodeResponse(errs.ErrCodeCryptoFailure, "password wrap failed: "+err.Error())
	}
	pwOut := make([]byte, 0, len(salt)+len(pwIV)+len(pwCT))
	pwOut = append(pwOut, salt...)
	pwOut = append(pwOut, pwIV...)
	pwOut = append(pwOut, pwCT...)

	// device wrap
	devWrapped, err := aesGCMSeal(deviceKeyBuf.Bytes(), dek)
	if err != nil {
		return empty, errs.CodeResponse(errs.ErrCodeCryptoFailure, "device wrap failed: "+err.Error())
	}

	data := proto.DEKGenerateAndWrapDualResponseData{
		PasswordWrappedDEKB64: base64.StdEncoding.EncodeToString(pwOut),
		DeviceWrappedDEKB64:   devWrapped,
	}
	return data, proto.BaseResponse{Success: true}
}
