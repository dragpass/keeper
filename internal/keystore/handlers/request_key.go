// request_key.go — per-device request-signing key handlers.
//
// HandleRequestKeyGenerate / HandleRequestKeyStatus / HandleSignRequest —
// lifecycle of the Ed25519 keypair used to sign ordinary API requests.
//
// This key is never used for unwrap / login challenge / recovery — fully
// separated from the identity keypair (RSA, identity.go) in slot / algorithm
// / handler.
//
// The canonical_request input must contain only meta information
// (method/path/timestamp, etc.). The handler does not inspect the input, so
// the client (Extension/Keeper wrapper) must ensure it never includes
// plaintext payload / token / secret itself.

package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// fingerprintBase64Public — same formula as server-side services.fingerprintBase64Public.
// hex(sha256(base64 public key)). Both sides see the same identifier for the same key.
func fingerprintBase64Public(b64 string) string {
	sum := sha256.Sum256([]byte(b64))
	return hex.EncodeToString(sum[:])
}

// HandleRequestKeyGenerate — generates a new Ed25519 keypair if no active key exists.
//
// If an active key is already present, it does not create a new one and only
// returns the existing key's meta — idempotent. Rotation has its own action
// (rotate_request_key_*), so this action is for status checks after
// enrollment / re-enrollment.
func HandleRequestKeyGenerate(d Deps, req proto.RequestKeyGenerateRequest) proto.BaseResponse {
	d.Logger.Println("request key generate processing...")

	// If an active key already exists, return only its meta (idempotent).
	if existing, err := keychain.GetRequestSigningPublicKey(d.Store); err == nil && existing != "" {
		fp := fingerprintBase64Public(existing)
		d.Logger.Println("request key generate: active key already present, returning meta")
		return proto.BaseResponse{Success: true, Data: proto.RequestKeyGenerateResponseData{
			PublicKey:   existing,
			Fingerprint: fp,
		}}
	}

	pub, priv, err := ed25519.GenerateKey(d.Random())
	if err != nil {
		d.Logger.Printf("request key generate: ed25519 keygen failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "request key keygen failed: "+err.Error())
	}

	// private key is 64B (32B seed || 32B public) — stored as base64.
	// During the brief encoding window we use a raw slice and zeroize after
	// encoding. memguard is unusable here because it conflicts with the
	// crypto/ed25519 weak-ref cache.
	defer secure.Zeroize(priv)
	privB64 := base64.StdEncoding.EncodeToString(priv)
	defer secure.WipeString(&privB64)

	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if err := keychain.SaveRequestSigningPrivateKey(d.Store, privB64); err != nil {
		d.Logger.Printf("request key generate: save priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save request priv key failed: "+err.Error())
	}
	if err := keychain.SaveRequestSigningPublicKey(d.Store, pubB64); err != nil {
		d.Logger.Printf("request key generate: save pub failed: %v", err)
		// Partial failure — only priv is saved. The next generate call sees
		// GetRequestSigningPublicKey as not_found and creates anew, but the
		// priv slot is overwritten, so it never gets stuck.
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save request pub key failed: "+err.Error())
	}

	d.Logger.Println("request key generate: new ed25519 keypair saved")
	return proto.BaseResponse{Success: true, Data: proto.RequestKeyGenerateResponseData{
		PublicKey:   pubB64,
		Fingerprint: fingerprintBase64Public(pubB64),
	}}
}

// HandleRequestKeyStatus — active key presence + public key + fingerprint.
// Active-key absence signals "normal — not enrolled yet", so it returns 200
// with has_active=false.
func HandleRequestKeyStatus(d Deps, req proto.RequestKeyStatusRequest) proto.BaseResponse {
	d.Logger.Println("request key status processing...")

	pubB64, err := keychain.GetRequestSigningPublicKey(d.Store)
	if err != nil || pubB64 == "" {
		return proto.BaseResponse{Success: true, Data: proto.RequestKeyStatusResponseData{
			HasActive: false,
		}}
	}
	return proto.BaseResponse{Success: true, Data: proto.RequestKeyStatusResponseData{
		HasActive:   true,
		PublicKey:   pubB64,
		Fingerprint: fingerprintBase64Public(pubB64),
	}}
}

// HandleSignRequest — signs canonical_request with the active key.
//
// canonical_request must never contain plaintext payload / token / secret
// itself. The handler does not inspect the input, so this is the client's
// responsibility.
//
// If there is no active key → not_found, the caller triggers the enroll flow.
//
// Once this Keeper owns a device id (device_id_ensure), it signs only a
// dp-req-v1 canonical whose device field is that id, so no caller gets a
// request signed as another device. Before that there is nothing to compare
// with and any canonical is signed, as before.
func HandleSignRequest(d Deps, req proto.SignRequestRequest) proto.BaseResponse {
	d.Logger.Println("sign request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if resp, ok := checkCanonicalDeviceID(d, req.CanonicalRequest); !ok {
		return resp
	}
	return signRequestCanonical(d, req.CanonicalRequest)
}

// canonicalRequestFields is the dp-req-v1 layout ariadne verifies: version,
// method, path, query, timestamp, nonce, body hash, account id, token id,
// device id, one per line.
const canonicalRequestFields = 10

// checkCanonicalDeviceID refuses a canonical request whose device field is not
// the stored device id. A stored id that cannot be read refuses too: signing
// then would skip the check exactly when it is in doubt.
func checkCanonicalDeviceID(d Deps, canonical string) (proto.BaseResponse, bool) {
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		d.Logger.Printf("sign request: device id unreadable: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "device id is unreadable"), false
	}
	if !found {
		return proto.BaseResponse{}, true
	}
	fields := strings.Split(canonical, "\n")
	if len(fields) != canonicalRequestFields || fields[0] != "dp-req-v1" || fields[canonicalRequestFields-1] != deviceID {
		d.Logger.Println("sign request: refused, canonical device id is not this Keeper's")
		return errs.CodeResponse(errs.ErrCodeValidation, "canonical_request device id does not match this device"), false
	}
	return proto.BaseResponse{}, true
}

func signRequestCanonical(d Deps, canonical string) proto.BaseResponse {

	privB64, err := keychain.GetRequestSigningPrivateKey(d.Store)
	if err != nil || privB64 == "" {
		d.Logger.Println("sign request: no active request key")
		return errs.CodeResponse(errs.ErrCodeNotFound, "request signing key not found. enroll first")
	}

	rawPriv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		d.Logger.Printf("sign request: base64 decode of stored priv failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "stored request priv key corrupt")
	}
	if len(rawPriv) != ed25519.PrivateKeySize {
		d.Logger.Printf("sign request: stored priv key wrong size: %d", len(rawPriv))
		return errs.CodeResponse(errs.ErrCodeStorageFailure,
			fmt.Sprintf("stored request priv key length=%d want %d", len(rawPriv), ed25519.PrivateKeySize))
	}

	// crypto/ed25519 uses a weak-ref-based fips140cache, so casting a memguard
	// mlock'd region directly to PrivateKey fails to register a weak handle
	// (panic). During the short signing window we use the raw slice as-is and
	// discard via defer zeroize.
	defer secure.Zeroize(rawPriv)

	sig := ed25519.Sign(ed25519.PrivateKey(rawPriv), []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	pubB64, _ := keychain.GetRequestSigningPublicKey(d.Store)

	d.Logger.Println("sign request: ed25519 signature produced")
	return proto.BaseResponse{Success: true, Data: proto.SignRequestResponseData{
		Signature:   sigB64,
		PublicKey:   pubB64,
		Fingerprint: fingerprintBase64Public(pubB64),
	}}
}
