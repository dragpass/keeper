package proto

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The credential sinks open a caller-chosen AAD; a reserved domain is refused
// there as it is on the seal side, in every Base64 alphabet the decoder takes.
func TestCredentialSealedPayloadRefusesReservedAADDomains(t *testing.T) {
	iv := base64.StdEncoding.EncodeToString(make([]byte, 12))
	ct := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, aad := range []string{
		"dragpass.drag.audit|1|a|b|3|c",
		"dragpass.message|1|a|b|3|9",
		"dragpass.message.display|1",
	} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			err := validateCredentialSealedPayload(iv, ct, enc.EncodeToString([]byte(aad)))
			if err == nil || !strings.Contains(err.Error(), "aad_b64") {
				t.Fatalf("reserved AAD %q accepted: %v", aad, err)
			}
		}
	}
	ok := "11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222|credential|1|3"
	if err := validateCredentialSealedPayload(iv, ct, base64.StdEncoding.EncodeToString([]byte(ok))); err != nil {
		t.Fatalf("credential canonical refused: %v", err)
	}
	// dragpass.room stays open to the Keeper's own room-row-name route.
	if err := validateCredentialSealedPayload(iv, ct, base64.StdEncoding.EncodeToString([]byte("dragpass.room|1|x"))); err != nil {
		t.Fatalf("room AAD refused: %v", err)
	}
}

func TestGrantContextValidation(t *testing.T) {
	good := GrantContext{
		Policy: GrantPolicyAuditOnlyV1, OrgID: "11111111-1111-4111-8111-111111111111",
		GroupID: "22222222-2222-4222-8222-222222222222", DekVersion: 3,
	}
	if err := validateGrantContext(&good, "grant_context"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*GrantContext){
		"policy":  func(c *GrantContext) { c.Policy = "audit_only_v2" },
		"org":     func(c *GrantContext) { c.OrgID = "ORG" },
		"group":   func(c *GrantContext) { c.GroupID = "" },
		"version": func(c *GrantContext) { c.DekVersion = 0 },
	} {
		c := good
		mutate(&c)
		if err := validateGrantContext(&c, "grant_context"); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	open := GroupSessionOpenRequest{EncryptedGroupDEK: "eA==", OrgID: "33333333-3333-4333-8333-333333333333", GrantContext: &good}
	if err := open.Validate(); err == nil {
		t.Fatal("org_id that differs from grant_context.org_id accepted")
	}
}
