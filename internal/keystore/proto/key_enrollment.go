package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

func AccountKeyEnrollmentCanonical(accountID, fingerprint string) string {
	return strings.Join([]string{"dragpass.keyenrollment", "1", accountID, fingerprint}, "|")
}

// RecoveryKeyReissueCanonical is what auth_recovery_reissue_prepare signs with
// the private key it wraps. ariadne builds the same string and verifies the
// signature against the account's current public key, so an RK24 that wraps
// any other key is refused.
func RecoveryKeyReissueCanonical(version uint, authSeed, wrappedKeeper string) string {
	seed := sha256.Sum256([]byte(authSeed))
	wrapped := sha256.Sum256([]byte(wrappedKeeper))
	return strings.Join([]string{
		"dragpass.recoverykeyreissue", "1", strconv.FormatUint(uint64(version), 10),
		hex.EncodeToString(seed[:]), hex.EncodeToString(wrapped[:]),
	}, "|")
}
