// refresh_server_keys.go — when the Extension forwards the server's
// `GET /api/v1/system/server-keys` response as-is, the Keeper verifies Root
// signatures and refreshes the multi-version server public-key slots in the
// Keychain.

package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/dragpass/keeper/internal/keystore/anchor"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// SystemServerKeyEntry mirrors the shape of one key in the server's
// `GET /system/server-keys` response.
type SystemServerKeyEntry struct {
	Version       uint      `json:"version"`
	PublicKeyPEM  string    `json:"public_key_pem"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Status        string    `json:"status"`                   // "active" | "deprecated"
	RootSignature string    `json:"root_signature,omitempty"` // base64
}

// RefreshServerKeysRequest is the action input. Same shape as the server response.
type RefreshServerKeysRequest struct {
	Keys                     []SystemServerKeyEntry `json:"keys"`
	RootPublicKeyFingerprint string                 `json:"root_public_key_fingerprint,omitempty"`
}

// Validate only validates the input shape itself.
func (r RefreshServerKeysRequest) Validate() error {
	if len(r.Keys) == 0 {
		return errors.New("keys is empty")
	}
	activeCount := 0
	for i, k := range r.Keys {
		if k.Version == 0 {
			return fmt.Errorf("keys[%d].version must be >= 1", i)
		}
		if k.PublicKeyPEM == "" {
			return fmt.Errorf("keys[%d].public_key_pem is empty", i)
		}
		switch k.Status {
		case "active":
			activeCount++
		case "deprecated":
		default:
			return fmt.Errorf("keys[%d].status invalid: %q (must be active|deprecated)", i, k.Status)
		}
	}
	if activeCount != 1 {
		return fmt.Errorf("must have exactly one active key, got %d", activeCount)
	}
	return nil
}

// RefreshServerKeysResponseData is the action response.
type RefreshServerKeysResponseData struct {
	UpdatedVersions []uint `json:"updated_versions"`
	ActiveVersion   uint   `json:"active_version"`
	RootVerified    bool   `json:"root_verified"`
	Rejected        []uint `json:"rejected"`
}

// HandleRefreshServerKeys refreshes the multi-version server public-key slots.
func HandleRefreshServerKeys(d Deps, req RefreshServerKeysRequest) proto.BaseResponse {
	d.Logger.Println("refresh_server_keys request processing...")

	if err := req.Validate(); err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "validation: "+err.Error())
	}

	rootPEM, err := anchor.RootPublicKeyPEM()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "load embedded root: "+err.Error())
	}
	rootEmbedded := rootPEM != ""

	// If the Root is embedded, require fingerprint match + signature verify on every entry.
	rootVerified := false
	if rootEmbedded {
		embeddedFp, err := anchor.ComputeRootKeyFingerprint()
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeInternal, "compute root fingerprint: "+err.Error())
		}
		if req.RootPublicKeyFingerprint == "" {
			return errs.CodeResponse(errs.ErrCodeValidation, "root pubkey embedded but server response has no fingerprint")
		}
		if req.RootPublicKeyFingerprint != embeddedFp {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, fmt.Sprintf("root fingerprint mismatch: server=%s embedded=%s",
				req.RootPublicKeyFingerprint, embeddedFp))
		}
		// Also compare against the TOFU pin (if one is already pinned)
		pinned, _ := keychain.GetRootPublicKeyFingerprint(d.Store)
		if pinned != "" && pinned != embeddedFp {
			d.Logger.Printf("root fingerprint update detected (was=%s now=%s) — accepting embedded value", pinned, embeddedFp)
		}

		// verify root_signature on each key
		for i, k := range req.Keys {
			if k.RootSignature == "" {
				return errs.CodeResponse(errs.ErrCodeValidation, fmt.Sprintf("keys[%d] (v%d): root_signature missing — required when root pubkey embedded", i, k.Version))
			}
			sigBytes, err := base64.StdEncoding.DecodeString(k.RootSignature)
			if err != nil {
				return errs.CodeResponse(errs.ErrCodeValidation, fmt.Sprintf("keys[%d] (v%d): decode root_signature: %v", i, k.Version, err))
			}
			payload := anchor.BuildServerKeyRootSigPayload(k.Version, k.PublicKeyPEM, k.IssuedAt.Unix(), k.ExpiresAt.Unix())
			if err := anchor.VerifyServerKeyRootSignature(payload, sigBytes); err != nil {
				return errs.CodeResponse(errs.ErrCodeCryptoFailure, fmt.Sprintf("keys[%d] (v%d): root signature verify: %v", i, k.Version, err))
			}
		}
		rootVerified = true
	}

	// Verification passed — batch-refresh the Keychain.
	updated := make([]uint, 0, len(req.Keys))
	var activeVersion uint
	var activeKeyPEM string
	for _, k := range req.Keys {
		if err := keychain.SaveServerPublicKeyForVersion(d.Store, k.Version, k.PublicKeyPEM); err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, fmt.Sprintf("keys[v%d] save: %v", k.Version, err))
		}
		updated = append(updated, k.Version)
		if k.Status == "active" {
			activeVersion = k.Version
			activeKeyPEM = k.PublicKeyPEM
		}
	}
	if err := keychain.SaveActiveServerKeyVersion(d.Store, activeVersion); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save active version: "+err.Error())
	}
	// Mirror the active key PEM into the legacy single slot (challenge compatibility).
	if err := keychain.SaveServerPublicKey(d.Store, activeKeyPEM); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mirror legacy slot: "+err.Error())
	}
	// fingerprint TOFU pin — store if the response provides one
	if req.RootPublicKeyFingerprint != "" {
		if err := keychain.SaveRootPublicKeyFingerprint(d.Store, req.RootPublicKeyFingerprint); err != nil {
			d.Logger.Printf("warn: failed to pin root fingerprint: %v", err)
		}
	}

	d.Logger.Printf("refresh_server_keys done — updated=%v active=v%d root_verified=%v",
		updated, activeVersion, rootVerified)
	return proto.BaseResponse{
		Success: true,
		Data: RefreshServerKeysResponseData{
			UpdatedVersions: updated,
			ActiveVersion:   activeVersion,
			RootVerified:    rootVerified,
			Rejected:        []uint{},
		},
	}
}
