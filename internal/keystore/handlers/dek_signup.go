// dek_signup.go — signup-flow Personal DEK generation + wrap handlers (two).
//
//   - HandleDEKGenerateAndWrapDual     : wraps with both password + deviceKey
//                                        in one call (composite action used by
//                                        the Extension signup flow).
//   - HandleDEKGenerateAndWrapPassword : wraps with password only (legacy single-wrap).
//
// Both handlers generate a new 32B DEK via d.FillRandom and wrap with a
// PBKDF2 KEK. The device wrap uses AES-GCM seal directly with deviceKey.

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

	// fetch deviceKey internally — never accept it via the IPC payload
	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	// generate salt + DEK
	salt := make([]byte, dekSaltLength)
	if err := d.FillRandom(salt); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate salt: "+err.Error())
	}
	dek := make([]byte, 32)
	if err := d.FillRandom(dek); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate dek: "+err.Error())
	}
	defer secure.Zeroize(dek)

	// password wrap
	kek := pbkdf2.Key(pwBuf.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)
	pwIV, pwCT, err := aesGCMSealSplit(kek, dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "password wrap failed: "+err.Error())
	}
	pwOut := make([]byte, 0, len(salt)+len(pwIV)+len(pwCT))
	pwOut = append(pwOut, salt...)
	pwOut = append(pwOut, pwIV...)
	pwOut = append(pwOut, pwCT...)

	// device wrap
	devWrapped, err := aesGCMSeal(deviceKeyBuf.Bytes(), dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "device wrap failed: "+err.Error())
	}

	d.Logger.Println("dek generate and wrap dual successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKGenerateAndWrapDualResponseData{
		PasswordWrappedDEKB64: base64.StdEncoding.EncodeToString(pwOut),
		DeviceWrappedDEKB64:   devWrapped,
	}}
}

// HandleDEKGenerateAndWrapPassword is the signup flow's generateDEK + wrapDEKWithPassword.
func HandleDEKGenerateAndWrapPassword(d Deps, req proto.DEKGenerateAndWrapPasswordRequest) proto.BaseResponse {
	d.Logger.Println("dek generate and wrap password request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// protect password with memguard and zeroize the original string's backing bytes
	password := req.Password
	pwBuf := memguard.NewBufferFromBytes([]byte(password))
	secure.WipeString(&password)
	secure.WipeString(&req.Password)
	defer pwBuf.Destroy()

	// generate salt
	salt := make([]byte, dekSaltLength)
	if err := d.FillRandom(salt); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate salt: "+err.Error())
	}

	// generate DEK + protect with memguard
	dek := make([]byte, 32)
	if err := d.FillRandom(dek); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate dek: "+err.Error())
	}
	defer secure.Zeroize(dek)

	// derive KEK with PBKDF2. Pass the password backing bytes directly as input.
	kek := pbkdf2.Key(pwBuf.Bytes(), salt, dekPBKDF2Iterations, dekKEKLength, sha256.New)
	defer secure.Zeroize(kek)

	iv, ciphertext, err := aesGCMSealSplit(kek, dek)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrap dek failed: "+err.Error())
	}

	// Base64(salt || iv || ciphertext)
	out := make([]byte, 0, len(salt)+len(iv)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, ciphertext...)

	d.Logger.Println("dek generate and wrap password successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKGenerateAndWrapPasswordResponseData{
		EncryptedDEKB64: base64.StdEncoding.EncodeToString(out),
	}}
}
