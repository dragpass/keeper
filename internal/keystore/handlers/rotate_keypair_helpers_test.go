// rotate_keypair_helpers_test.go — confirmation payload factories shared by
// rotate_keypair_{prepare,promote,status_abort}_test.go.
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func rotateConfirmationPayloadForTest(t *testing.T, token, pendingPub string, expiresAt int64) string {
	t.Helper()
	pendingPubB64 := base64.StdEncoding.EncodeToString([]byte(pendingPub))
	sum := sha256.Sum256([]byte(pendingPubB64))
	raw, err := json.Marshal(rotateKeyConfirmationPayload{
		Type:                   rotateKeyConfirmationPayloadType,
		ConfirmationToken:      token,
		AccountID:              "account-test",
		PendingPublicKeySHA256: hex.EncodeToString(sum[:]),
		ExpiresAt:              expiresAt,
	})
	if err != nil {
		t.Fatalf("confirmation payload: %v", err)
	}
	return string(raw)
}

func futureRotateConfirmationPayloadForTest(t *testing.T, token, pendingPub string) string {
	t.Helper()
	return rotateConfirmationPayloadForTest(t, token, pendingPub, time.Now().Add(time.Hour).Unix())
}
