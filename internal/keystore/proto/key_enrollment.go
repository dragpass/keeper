package proto

import "strings"

func AccountKeyEnrollmentCanonical(accountID, fingerprint string) string {
	return strings.Join([]string{"dragpass.keyenrollment", "1", accountID, fingerprint}, "|")
}
