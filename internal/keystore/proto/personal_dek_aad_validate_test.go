package proto

import (
	"encoding/base64"
	"testing"
)

// The personal caller-AAD seal must not mint a ciphertext under a domain the
// Keeper builds itself, or a caller could seal a bound personal token with
// an expiry the bound action never chose.
func TestDEKUnwrapAndEncryptWithAADRefusesReservedDomains(t *testing.T) {
	for _, aad := range []string{
		"dragpass.drag.token|1|personal|11111111-1111-4111-8111-111111111111|-|1|-|never",
		"dragpass.drag.audit|1|x",
		MessageAADDomain + "|1",
	} {
		req := DEKUnwrapAndEncryptWithAADRequest{
			PlaintextB64: base64.StdEncoding.EncodeToString([]byte("p")),
			AADB64:       base64.StdEncoding.EncodeToString([]byte(aad)),
		}
		if req.Validate() == nil {
			t.Fatalf("reserved AAD %q accepted", aad)
		}
	}
	ok := DEKUnwrapAndEncryptWithAADRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("p")),
		AADB64:       base64.StdEncoding.EncodeToString([]byte("dragpass.personal.entry|1")),
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("ordinary AAD refused: %v", err)
	}
}
