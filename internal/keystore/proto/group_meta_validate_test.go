// group_meta_validate_test.go — GroupEncryptMetaRequest / GroupDecryptMetaRequest
// Validate() regression guards. Mirrors group_encrypt_validate_test.go.
//
// VALID_HANDLE is declared in aes_actions_validate_test.go (same package).
package proto

import (
	"strings"
	"testing"
)

func TestGroupDecryptMeta_Validate(t *testing.T) {
	valid := GroupDecryptMetaRequest{
		GroupHandle: VALID_HANDLE,
		MetaFields:  map[string]string{"label": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}, // ≥ 12B
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name string
		req  GroupDecryptMetaRequest
		want string
	}{
		{"bad handle", GroupDecryptMetaRequest{GroupHandle: "", MetaFields: map[string]string{"l": "AAAAAAAAAAAAAAAAAAAA"}}, "group_handle"},
		{"empty meta_fields", GroupDecryptMetaRequest{GroupHandle: VALID_HANDLE}, "meta_fields"},
		{"empty key", GroupDecryptMetaRequest{GroupHandle: VALID_HANDLE, MetaFields: map[string]string{"": "AAAAAAAAAAAAAAAAAAAA"}}, "meta_fields"},
		{"cipher too short", GroupDecryptMetaRequest{GroupHandle: VALID_HANDLE, MetaFields: map[string]string{"l": "AA=="}}, "meta_fields"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must mention %q, got %q", tc.want, err.Error())
			}
		})
	}
}

func TestGroupDecryptMeta_Validate_SkipsEmptyValue(t *testing.T) {
	// An empty ciphertext value is allowed (skipped at decrypt time).
	r := GroupDecryptMetaRequest{
		GroupHandle: VALID_HANDLE,
		MetaFields:  map[string]string{"cleared": ""},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("empty value must be allowed, got %v", err)
	}
}

func TestGroupEncryptMeta_Validate(t *testing.T) {
	valid := GroupEncryptMetaRequest{
		GroupHandle: VALID_HANDLE,
		Fields:      map[string]string{"label": "plaintext"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name string
		req  GroupEncryptMetaRequest
		want string
	}{
		{"bad handle", GroupEncryptMetaRequest{GroupHandle: "", Fields: map[string]string{"l": "x"}}, "group_handle"},
		{"empty fields", GroupEncryptMetaRequest{GroupHandle: VALID_HANDLE}, "fields"},
		{"empty key", GroupEncryptMetaRequest{GroupHandle: VALID_HANDLE, Fields: map[string]string{"": "x"}}, "fields"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must mention %q, got %q", tc.want, err.Error())
			}
		})
	}
}

func TestGroupEncryptMeta_Validate_DoesNotEchoSecret(t *testing.T) {
	r := GroupEncryptMetaRequest{
		GroupHandle: "", // forces failure before any field is inspected
		Fields:      map[string]string{"label": SECRET_VALUE},
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("validation error must not echo input value, got %q", err.Error())
	}
}
