package proto

import (
	"errors"
	"testing"
)

// A split accepts at most 32 recipients, the server's participant cap
// (ariadne splitMaxParticipants): 32 is accepted and 33 is a validation
// error on recipient_public_keys.
func TestArchiveKeySplitRequestRecipientCap(t *testing.T) {
	request := func(n int) ArchiveKeySplitRequest {
		keys := make([]string, n)
		for i := range keys {
			keys[i] = testValidPubPEM
		}
		return ArchiveKeySplitRequest{
			OperationID: "77777777-7777-4777-8777-777777777777", OrgID: "22222222-2222-4222-8222-222222222222",
			ThresholdN: 2, RecipientPublicKeys: keys,
		}
	}
	if err := request(32).Validate(); err != nil {
		t.Fatalf("32 recipients refused: %v", err)
	}
	err := request(33).Validate()
	var v *ValidationError
	if !errors.As(err, &v) || v.Field != "recipient_public_keys" {
		t.Fatalf("33 recipients: err = %v", err)
	}
}
