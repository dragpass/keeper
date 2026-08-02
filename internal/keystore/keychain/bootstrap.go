package keychain

// Bootstrap seeds the v1 server key without replacing refreshed key state.

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

// EnsureServerPublicKey seeds v1 only when no active version exists.
func EnsureServerPublicKey(store SecretStore, log logger.Logger) error {
	if v, err := GetActiveServerKeyVersion(store); err == nil && v >= 1 {
		return nil
	}

	// Decode the hard-coded v1 PEM.
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to decode hardcoded server public key: %v", err)
	}
	pem := string(serverPubKeyBytes)

	if err := SaveServerPublicKeyForVersion(store, bootstrapServerKeyVersion, pem); err != nil {
		return fmt.Errorf("failed to save server public key v%d: %v", bootstrapServerKeyVersion, err)
	}

	if err := SaveActiveServerKeyVersion(store, bootstrapServerKeyVersion); err != nil {
		return fmt.Errorf("failed to save active server key version: %v", err)
	}

	log.Printf("bootstrap: server public key v%d seeded into Keychain", bootstrapServerKeyVersion)
	return nil
}
