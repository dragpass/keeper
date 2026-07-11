// guest_transcrypt.go — HandleGroupTranscryptForGuest + guest-share crypto.
//
// Re-encrypts an org Group-DEK token into an external guest share entirely
// inside Keeper-protected memory: the token plaintext is decrypted behind the
// GroupSessions opaque handle, immediately re-encrypted under a fresh one-time
// guest key K, and zeroized. The response carries only the guest ciphertext +
// K — the plaintext / raw Group DEK never enter the Extension JS heap.
//
// The crypto is byte-compatible with the admin SPA guest viewer
// (dragpass/app/src/shared/lib/guest-share-crypto.ts). See guest_share.go for
// the wire format. Any parameter drift here breaks WebCrypto decryption on the
// viewer side, so the constants below mirror that file exactly.

package handlers

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const (
	// guestKeyLen — raw one-time guest key K length (bytes). Mirrors
	// `crypto.getRandomValues(new Uint8Array(32))` in guest-share-crypto.ts.
	guestKeyLen = 32
	// guestPBKDF2Iterations — mirrors PBKDF2_ITERATIONS (200_000) with
	// SHA-256 in guest-share-crypto.ts.
	guestPBKDF2Iterations = 200_000
	// guestHKDFInfo — mirrors the HKDF `info` label in guest-share-crypto.ts.
	guestHKDFInfo = "dragpass-guest-v1"
)

// HandleGroupTranscryptForGuest decrypts an org token (encrypted directly with
// the raw Group DEK) and re-encrypts it as an external guest share. The whole
// decrypt→re-encrypt→zeroize cycle runs inside the GroupSessions.Use closure,
// so the plaintext never outlives the Group DEK access and never reaches the
// response.
func HandleGroupTranscryptForGuest(d Deps, req proto.GroupTranscryptForGuestRequest) proto.BaseResponse {
	d.Logger.Println("group transcrypt for guest request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}

	// Salt is optional and only present alongside a passphrase (Validate
	// enforces together-or-neither). The app sends standard Base64.
	var salt []byte
	if req.PassphraseSalt != "" {
		salt, resp, ok = decodeBase64(req.PassphraseSalt, "passphrase_salt")
		if !ok {
			return resp
		}
	}

	var guestCiphertext, guestKey string
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		plaintext, err := aesGCMOpen(groupDEK, iv, ciphertext)
		if err != nil {
			return errors.New("decrypt failed: " + err.Error())
		}
		defer secure.Zeroize(plaintext)

		ct, key, err := encryptForGuest(plaintext, req.Passphrase, salt)
		if err != nil {
			return errors.New("guest re-encrypt failed: " + err.Error())
		}
		guestCiphertext = ct
		guestKey = key
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group transcrypt for guest")
	}

	// Best-effort wipe of the passphrase now that derivation is done.
	if req.Passphrase != "" {
		secure.WipeString(&req.Passphrase)
	}

	d.Logger.Println("group transcrypt for guest successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupTranscryptForGuestResponseData{
		GuestCiphertext: guestCiphertext,
		GuestKey:        guestKey,
	}}
}

// encryptForGuest generates a fresh 32B guest key K, derives the AES-GCM key
// from it (see deriveGuestAESKey), and returns:
//   - ciphertext: standard Base64 of IV(12) ‖ AES-GCM(plaintext) with tag
//   - keyB64url:  Base64URL (no padding) of the raw K (the link fragment)
//
// Mirrors encryptForGuest in guest-share-crypto.ts (new random K + IV per
// call). K is zeroized before returning; only its Base64URL form escapes.
func encryptForGuest(plaintext []byte, passphrase string, salt []byte) (ciphertext string, keyB64url string, err error) {
	k := make([]byte, guestKeyLen)
	if _, err := rand.Read(k); err != nil {
		return "", "", err
	}
	defer secure.Zeroize(k)

	aesKey, err := deriveGuestAESKey(k, passphrase, salt)
	if err != nil {
		return "", "", err
	}
	defer secure.Zeroize(aesKey)

	// aesGCMSealSplit generates a fresh 12B IV via crypto/rand and returns the
	// ciphertext with the 128-bit GCM tag appended — matching WebCrypto
	// AES-GCM defaults.
	iv, ct, err := aesGCMSealSplit(aesKey, plaintext)
	if err != nil {
		return "", "", err
	}
	payload := make([]byte, 0, len(iv)+len(ct))
	payload = append(payload, iv...)
	payload = append(payload, ct...)

	// EncodeToString reads k before the deferred Zeroize runs at return.
	return base64.StdEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(k),
		nil
}

// deriveGuestAESKey mirrors deriveAesKey in guest-share-crypto.ts:
//   - no passphrase/salt → K itself is the AES key.
//   - otherwise → AES key = HKDF-SHA256(
//     ikm  = K ‖ PBKDF2-SHA256(passphrase, salt, 200000, 32B),
//     salt = salt, info = "dragpass-guest-v1", 32B).
//
// The returned slice is a fresh 32B buffer the caller must zeroize.
func deriveGuestAESKey(k []byte, passphrase string, salt []byte) ([]byte, error) {
	if passphrase == "" || len(salt) == 0 {
		out := make([]byte, len(k))
		copy(out, k)
		return out, nil
	}

	pmat, err := pbkdf2.Key(sha256.New, passphrase, salt, guestPBKDF2Iterations, 32)
	if err != nil {
		return nil, err
	}
	defer secure.Zeroize(pmat)

	ikm := make([]byte, 0, len(k)+len(pmat))
	ikm = append(ikm, k...)
	ikm = append(ikm, pmat...)
	defer secure.Zeroize(ikm)

	return hkdf.Key(sha256.New, ikm, salt, guestHKDFInfo, 32)
}
