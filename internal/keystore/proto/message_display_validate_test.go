// message_display_validate_test.go — structural validation of the two message
// display requests, and the two canonical builders.
//
// The canonical tests carry literal expected strings on purpose. D1
// (packages/crypto) and D2 (ariadne) build the same bytes from the same inputs;
// if any of the three drifts by one character, every message either fails to
// open or fails signature verification. A literal is the only assertion that
// catches that, and it is the one D2 matches against.
//
// The golden values come from dragpass-control-plane
// docs/testing/fixtures/secure-message-overlay-v1.json (test-only key and IV).

package proto

import (
	"reflect"
	"strings"
	"testing"
)

const (
	msgFixtureOrgID          = "11111111-1111-4111-8111-111111111111"
	msgFixtureGroupID        = "22222222-2222-4222-8222-222222222222"
	msgFixtureAuditTableID   = "33333333-3333-4333-8333-333333333333"
	msgFixtureDekVersion     = 7
	msgFixtureTokenExpiresAt = 2000000000
	msgFixtureIVB64          = "AAECAwQFBgcICQoL"
	msgFixtureCiphertextB64  = "A3C3fJWEsWitLPL4wogfCKOw7kyEDi0ZGBHUj02jpBEqwI2uZsRFqiUr5i0="
	msgFixtureChallenge      = "-XNnLWZpeHR1cmUtY2hhbGxlbmdlLTMyLWJ5dGVzI_E"
	msgFixtureAccountID      = "44444444-4444-4444-8444-444444444444"
	msgFixtureDigest         = "133e1d787a47823729f48499275ca92312effcb6cf31dfe80c25b219a4dcd6b8"
)

func msgStringPtr(v string) *string { return &v }

func msgValidPrepareRequest() MessageDisplayPrepareRequest {
	return MessageDisplayPrepareRequest{
		GroupHandle:          VALID_HANDLE,
		OrgID:                msgFixtureOrgID,
		GroupID:              msgFixtureGroupID,
		DekVersion:           msgFixtureDekVersion,
		MessageSchemaVersion: MessageSchemaVersion,
		TokenExpiresAt:       msgFixtureTokenExpiresAt,
		AuditTableID:         nil,
		IVB64:                msgFixtureIVB64,
		CiphertextB64:        msgFixtureCiphertextB64,
	}
}

func msgValidPermit() MessageDisplayPermit {
	return MessageDisplayPermit{
		Challenge:            msgFixtureChallenge,
		GroupID:              msgFixtureGroupID,
		DekVersion:           msgFixtureDekVersion,
		MessageSchemaVersion: MessageSchemaVersion,
		TokenExpiresAt:       msgFixtureTokenExpiresAt,
		AuditTableID:         nil,
		PayloadSHA256:        msgFixtureDigest,
		AccountID:            msgFixtureAccountID,
		OrgID:                msgFixtureOrgID,
		IssuedAt:             1700000000,
		ExpiresAt:            1700000030,
		ServerKeyVersion:     1,
		Signature:            "aGVsbG8=",
	}
}

// ────────────────────────────────────────────────────────────────────────
// Canonicals
// ────────────────────────────────────────────────────────────────────────

// TestMessageAADCanonical_GoldenVector — the AAD literal from the shared
// fixture's `aad_utf8`. The Keeper builds this itself; a caller cannot supply
// it, which is what keeps a drag token and a credential payload from opening
// through the display action.
func TestMessageAADCanonical_GoldenVector(t *testing.T) {
	got := MessageAADCanonical(
		msgFixtureOrgID, msgFixtureGroupID, msgFixtureDekVersion, MessageSchemaVersion, msgFixtureTokenExpiresAt,
	)
	want := "dragpass.message|1|11111111-1111-4111-8111-111111111111|" +
		"22222222-2222-4222-8222-222222222222|7|2000000000"
	if got != want {
		t.Fatalf("message AAD = %q, want %q", got, want)
	}
}

// TestMessageDisplayPermitCanonical_GoldenVector — the 14-item signing string
// on fixed inputs. ariadne's signer asserts the same literal.
func TestMessageDisplayPermitCanonical_GoldenVector(t *testing.T) {
	got := MessageDisplayPermitCanonical(msgValidPermit())
	want := "dragpass.message.display|1|" + msgFixtureChallenge + "|" +
		"44444444-4444-4444-8444-444444444444|" +
		"11111111-1111-4111-8111-111111111111|" +
		"22222222-2222-4222-8222-222222222222|" +
		"7|1|2000000000|-|" +
		"133e1d787a47823729f48499275ca92312effcb6cf31dfe80c25b219a4dcd6b8|" +
		"1700000000|1700000030|1"
	if got != want {
		t.Fatalf("permit canonical = %q, want %q", got, want)
	}
	if strings.Count(got, "|") != 13 {
		t.Fatalf("canonical must have 14 items separated by 13 pipes, got %d", strings.Count(got, "|"))
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("canonical must not end with a newline")
	}
}

// TestMessageDisplayPermitCanonical_AuditTableSlot — an audit message writes
// the table id where a normal message writes "-". The two must never
// canonicalize to the same bytes, or a permit for one would verify for the
// other.
func TestMessageDisplayPermitCanonical_AuditTableSlot(t *testing.T) {
	audit := msgValidPermit()
	audit.AuditTableID = msgStringPtr(msgFixtureAuditTableID)
	got := MessageDisplayPermitCanonical(audit)
	if !strings.Contains(got, "|"+msgFixtureAuditTableID+"|") {
		t.Fatalf("audit table id missing from canonical: %q", got)
	}
	if got == MessageDisplayPermitCanonical(msgValidPermit()) {
		t.Fatal("audit and non-audit permits canonicalize identically")
	}
	if MessageAuditTableSlot(nil) != "-" {
		t.Fatalf("absent audit table slot = %q, want %q", MessageAuditTableSlot(nil), "-")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Validate
// ────────────────────────────────────────────────────────────────────────

func TestMessageDisplayPrepare_Validate_AcceptsFixture(t *testing.T) {
	if err := msgValidPrepareRequest().Validate(); err != nil {
		t.Fatalf("fixture request rejected: %v", err)
	}
	audit := msgValidPrepareRequest()
	audit.AuditTableID = msgStringPtr(msgFixtureAuditTableID)
	if err := audit.Validate(); err != nil {
		t.Fatalf("audit-mode request rejected: %v", err)
	}
}

func TestMessageDisplayPrepare_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*MessageDisplayPrepareRequest)
		field string
	}{
		{"empty handle", func(r *MessageDisplayPrepareRequest) { r.GroupHandle = "" }, "group_handle"},
		{"uppercase org uuid", func(r *MessageDisplayPrepareRequest) {
			// The fixture ids are all digits, so ToUpper would be a no-op —
			// the case needs hex letters to actually test the casing rule.
			r.OrgID = "AABBCCDD-1111-4111-8111-111111111111"
		}, "org_id"},
		{"nil org uuid", func(r *MessageDisplayPrepareRequest) {
			r.OrgID = "00000000-0000-0000-0000-000000000000"
		}, "org_id"},
		{"unhyphenated group uuid", func(r *MessageDisplayPrepareRequest) {
			r.GroupID = strings.ReplaceAll(msgFixtureGroupID, "-", "")
		}, "group_id"},
		{"zero dek version", func(r *MessageDisplayPrepareRequest) { r.DekVersion = 0 }, "dek_version"},
		{"negative dek version", func(r *MessageDisplayPrepareRequest) { r.DekVersion = -1 }, "dek_version"},
		{"dek version over int32", func(r *MessageDisplayPrepareRequest) { r.DekVersion = 2147483648 }, "dek_version"},
		{"unsupported schema", func(r *MessageDisplayPrepareRequest) { r.MessageSchemaVersion = 2 }, "message_schema_version"},
		{"missing schema", func(r *MessageDisplayPrepareRequest) { r.MessageSchemaVersion = 0 }, "message_schema_version"},
		{"zero expiry", func(r *MessageDisplayPrepareRequest) { r.TokenExpiresAt = 0 }, "token_expires_at"},
		{"negative expiry", func(r *MessageDisplayPrepareRequest) { r.TokenExpiresAt = -1 }, "token_expires_at"},
		{"twelve-digit expiry", func(r *MessageDisplayPrepareRequest) { r.TokenExpiresAt = 100000000000 }, "token_expires_at"},
		{"malformed audit table", func(r *MessageDisplayPrepareRequest) { r.AuditTableID = msgStringPtr("not-a-uuid") }, "audit_table_id"},
		{"audit table dash", func(r *MessageDisplayPrepareRequest) { r.AuditTableID = msgStringPtr("-") }, "audit_table_id"},
		{"short iv", func(r *MessageDisplayPrepareRequest) { r.IVB64 = "AAECAwQFBgcICQo=" }, "iv_b64"},
		{"url-safe iv", func(r *MessageDisplayPrepareRequest) { r.IVB64 = "AAECAwQFBgcICQoL-w==" }, "iv_b64"},
		{"empty ciphertext", func(r *MessageDisplayPrepareRequest) { r.CiphertextB64 = "" }, "ciphertext_b64"},
		{"tag-only ciphertext", func(r *MessageDisplayPrepareRequest) {
			r.CiphertextB64 = "AAAAAAAAAAAAAAAAAAAAAA==" // 16B: a tag with no message
		}, "ciphertext_b64"},
		{"oversized ciphertext", func(r *MessageDisplayPrepareRequest) {
			r.CiphertextB64 = strings.Repeat("Q", 706) + "==" // 529B decoded
		}, "ciphertext_b64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := msgValidPrepareRequest()
			tc.apply(&r)
			err := r.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name %s, got %q", tc.field, err.Error())
			}
		})
	}
}

func TestMessageDisplayPermit_Validate_AcceptsFixture(t *testing.T) {
	if err := msgValidPermit().Validate(); err != nil {
		t.Fatalf("fixture permit rejected: %v", err)
	}
}

func TestMessageDisplayPermit_Validate_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*MessageDisplayPermit)
		field string
	}{
		{"short challenge", func(p *MessageDisplayPermit) { p.Challenge = msgFixtureChallenge[:42] }, "permit.challenge"},
		{"padded challenge", func(p *MessageDisplayPermit) {
			p.Challenge = msgFixtureChallenge[:41] + "=="
		}, "permit.challenge"},
		{"standard-base64 challenge", func(p *MessageDisplayPermit) {
			p.Challenge = strings.Replace(msgFixtureChallenge, "-", "+", 1)
		}, "permit.challenge"},
		{"malformed account", func(p *MessageDisplayPermit) { p.AccountID = "nope" }, "permit.account_id"},
		{"uppercase digest", func(p *MessageDisplayPermit) { p.PayloadSHA256 = strings.ToUpper(msgFixtureDigest) }, "permit.payload_sha256"},
		{"short digest", func(p *MessageDisplayPermit) { p.PayloadSHA256 = msgFixtureDigest[:63] }, "permit.payload_sha256"},
		{"zero issued_at", func(p *MessageDisplayPermit) { p.IssuedAt = 0 }, "permit.issued_at"},
		{"unsafe expires_at", func(p *MessageDisplayPermit) { p.ExpiresAt = 9007199254740992 }, "permit.expires_at"},
		{"zero key version", func(p *MessageDisplayPermit) { p.ServerKeyVersion = 0 }, "permit.server_key_version"},
		{"key version over uint32", func(p *MessageDisplayPermit) { p.ServerKeyVersion = 4294967296 }, "permit.server_key_version"},
		{"empty signature", func(p *MessageDisplayPermit) { p.Signature = "" }, "permit.signature"},
		{"unsupported permit schema", func(p *MessageDisplayPermit) { p.MessageSchemaVersion = 2 }, "permit.message_schema_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := msgValidPermit()
			tc.apply(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name %s, got %q", tc.field, err.Error())
			}
		})
	}
}

// TestMessageDisplay_Validate_DoesNotEchoInput — validation errors name fields,
// never values. The message payload is ciphertext, but the same rule that keeps
// a secret out of an error keeps a request payload out of one.
func TestMessageDisplay_Validate_DoesNotEchoInput(t *testing.T) {
	r := msgValidPrepareRequest()
	r.OrgID = SECRET_VALUE
	err := r.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("validation error echoed the input: %q", err.Error())
	}
}

// TestGroupDecryptWithAadForAppDisplay_Validate_CoversPermit — the display
// request validates its own fields and then the nested permit, so a malformed
// permit cannot ride in on a well-formed request.
func TestGroupDecryptWithAadForAppDisplay_Validate_CoversPermit(t *testing.T) {
	base := msgValidPrepareRequest()
	req := GroupDecryptWithAadForAppDisplayRequest{
		GroupHandle:          base.GroupHandle,
		OrgID:                base.OrgID,
		GroupID:              base.GroupID,
		DekVersion:           base.DekVersion,
		MessageSchemaVersion: base.MessageSchemaVersion,
		TokenExpiresAt:       base.TokenExpiresAt,
		AuditTableID:         base.AuditTableID,
		IVB64:                base.IVB64,
		CiphertextB64:        base.CiphertextB64,
		Permit:               msgValidPermit(),
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid display request rejected: %v", err)
	}
	req.Permit.Challenge = ""
	if err := req.Validate(); err == nil {
		t.Fatal("display request with a malformed permit accepted")
	}
}

// TestGroupDecryptWithAadForAppDisplayRequest_HasNoAADField — the invariant
// this whole design rests on: the caller describes which message it is, never
// how it is bound. A field named aad / domain / canonical appearing here would
// hand the caller the ability to open a credential payload.
func TestGroupDecryptWithAadForAppDisplayRequest_HasNoAADField(t *testing.T) {
	forbidden := []string{"aad", "domain", "canonical", "plaintext"}
	names := append(
		msgJSONTagNames(reflect.TypeOf(GroupDecryptWithAadForAppDisplayRequest{})),
		msgJSONTagNames(reflect.TypeOf(MessageDisplayPermit{}))...,
	)
	for _, name := range names {
		for _, bad := range forbidden {
			if strings.Contains(strings.ToLower(name), bad) {
				t.Fatalf("display request carries field %q — the AAD must stay Keeper-built", name)
			}
		}
	}
}

func msgJSONTagNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("json"); tag != "" {
			names = append(names, strings.Split(tag, ",")[0])
		}
	}
	return names
}
