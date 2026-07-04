package keychain

// bootstrap.go — seed the v1 server public key into the SecretStore on first
// boot.
//
// The `EnsureServerPublicKey` body from keystore root bootstrap.go moved here
// as an exported free function. Callers inject Store / Logger explicitly.
//
// **Semantics:** what used to fill only the single `server_public_key` slot
// is extended to also fill the new multi-version slots.
//
//   - server_public_key                    (legacy slot, mirror)
//   - server_public_key_v1                 (multi-version slot, v1)
//   - server_public_key_active_version     ("1")
//
// Already-filled slots are not overwritten — so that, even if the Extension
// has added v2/v3 via `refresh_server_keys`, bootstrap does not roll back to
// v1.

import (
	"encoding/base64"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/logger"
)

const (
	// serverPubKey is the Base64 of the v1 production server public key PEM.
	// When the production key rotates, v2/v3 are added dynamically via
	// `refresh_server_keys`. This constant itself is preserved as the
	// permanent v1 bootstrap anchor.
	serverPubKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3MG1NZ0FycExYVUhTemJmTGNudAowU1NhTEVhMnhCVms2SXNGTFlOVEl2NzdiZTdYdHhwZzRPd0hDc3JMMzAxV3R0Z2FEWDJBM0pYSnZEQ3FuNXJsCkZGbXNQY2RoeGxwbWdsRjNmODVSMW5KNlB6RW9Dekt1aVVjWE1pc21YSkJteGU2bEpDenZoWXJnbWpKT2xtMkUKY0xJUUpzelFvMUllRml3Mm5wN2c2TzNGSCt2aXRYSkRmV2toakV2RlFGQnd6aFp6cXZUT1o3SDNveUhGZ3RGSwpYeEJwOW5uN2N5L2RmRmVlYkRhSzBmVE1jQ2dEMWxGMjUwZDJMNDdPUmIrbkpEaklObjU4WkZxRVIvTkhWb3dpCnRyanFROU5mWG9rVVFYV2RCWHpjajZDMnNFbGRuR3B5TzFIUzhpYVEvM0RYeXZ2eG9oUWQrWTl3RDJqQnBOajkKYVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

	// bootstrapServerKeyVersion is the version number bootstrap fills.
	// Permanently 1.
	bootstrapServerKeyVersion uint = 1
)

// EnsureServerPublicKey fills the v1 production key into both the
// multi-version and legacy slots on first run. If the active_version pointer
// already exists, the seeding step is skipped — the newer state updated via
// refresh_server_keys is preserved.
//
// store: SecretStore — Keychain (production) / MemorySecretStore (test).
// log:   Logger — DI logger (StdLogger / MemoryLogger).
func EnsureServerPublicKey(store SecretStore, log logger.Logger) error {
	// If the active pointer already exists, bootstrap already ran or
	// refresh_server_keys already updated state → skip.
	if v, err := GetActiveServerKeyVersion(store); err == nil && v >= 1 {
		// However, if the legacy slot is empty (upgrade from an older
		// Keeper), only top up the mirror.
		if legacy, lerr := GetServerPublicKey(store); lerr != nil || legacy == "" {
			pem, perr := GetServerPublicKeyByVersion(store, v)
			if perr == nil && pem != "" {
				if err := SaveServerPublicKey(store, pem); err != nil {
					log.Printf("warn: failed to mirror active v%d to legacy slot: %v", v, err)
				}
			}
		}
		return nil
	}

	// Decode the hard-coded v1 PEM.
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to decode hardcoded server public key: %v", err)
	}
	pem := string(serverPubKeyBytes)

	// 1) fill multi-version slot v1
	if err := SaveServerPublicKeyForVersion(store, bootstrapServerKeyVersion, pem); err != nil {
		return fmt.Errorf("failed to save server public key v%d: %v", bootstrapServerKeyVersion, err)
	}

	// 2) active version pointer = 1
	if err := SaveActiveServerKeyVersion(store, bootstrapServerKeyVersion); err != nil {
		return fmt.Errorf("failed to save active server key version: %v", err)
	}

	// 3) mirror into the legacy single slot — backward compatible
	// (challenge verification uses it as a fallback).
	if err := SaveServerPublicKey(store, pem); err != nil {
		return fmt.Errorf("failed to save server public key (legacy slot): %v", err)
	}

	log.Printf("bootstrap: server public key v%d seeded into Keychain", bootstrapServerKeyVersion)
	return nil
}
