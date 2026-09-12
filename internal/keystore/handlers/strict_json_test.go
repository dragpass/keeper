// strict_json_test.go — the three things plain json.Unmarshal does silently
// and strictDecodeJSON must not.
//
// Each of them is a real failure mode for a signature-bound request: a
// duplicate key means verifying one value and decrypting under another, an
// unknown field means a caller smuggling something the contract does not
// describe, and a missing field means a zero value nobody chose.

package handlers

import (
	"strings"
	"testing"
)

type strictNested struct {
	Alpha string `json:"alpha"`
	Beta  int    `json:"beta"`
}

type strictOuter struct {
	Name     string       `json:"name"`
	Count    int          `json:"count"`
	Optional *string      `json:"optional"`
	Extra    string       `json:"extra,omitempty"`
	Skipped  string       `json:"-"`
	Nested   strictNested `json:"nested"`
}

func strictValidJSON() string {
	return `{"name":"n","count":1,"optional":null,"nested":{"alpha":"a","beta":2}}`
}

func TestStrictDecodeJSON_AcceptsExactObject(t *testing.T) {
	var out strictOuter
	if err := strictDecodeJSON([]byte(strictValidJSON()), &out); err != nil {
		t.Fatalf("valid object rejected: %v", err)
	}
	if out.Name != "n" || out.Count != 1 || out.Nested.Alpha != "a" || out.Nested.Beta != 2 {
		t.Fatalf("decoded value mismatch: %+v", out)
	}
	if out.Optional != nil {
		t.Fatalf("explicit null must decode to nil, got %v", *out.Optional)
	}
}

// TestStrictDecodeJSON_AcceptsOmittedOptionalFields — omitempty and "-" fields
// are not required keys, and an omitempty field may still be supplied.
func TestStrictDecodeJSON_AcceptsOmittedOptionalFields(t *testing.T) {
	body := `{"name":"n","count":1,"optional":"v","extra":"e","nested":{"alpha":"a","beta":2}}`
	var out strictOuter
	if err := strictDecodeJSON([]byte(body), &out); err != nil {
		t.Fatalf("object with an omitempty field rejected: %v", err)
	}
	if out.Extra != "e" || out.Optional == nil || *out.Optional != "v" {
		t.Fatalf("decoded value mismatch: %+v", out)
	}
}

func TestStrictDecodeJSON_RejectsDuplicateTopLevelKey(t *testing.T) {
	body := `{"name":"n","count":1,"count":2,"optional":null,"nested":{"alpha":"a","beta":2}}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("duplicate top-level key accepted")
	}
	if !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("error must name the duplicate, got %q", err.Error())
	}
}

// TestStrictDecodeJSON_RejectsDuplicateNestedKey — the walk has to reach every
// depth. This is the case the display request's nested permit lives in.
func TestStrictDecodeJSON_RejectsDuplicateNestedKey(t *testing.T) {
	body := `{"name":"n","count":1,"optional":null,"nested":{"alpha":"a","alpha":"b","beta":2}}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("duplicate nested key accepted")
	}
	if !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("error must name the duplicate, got %q", err.Error())
	}
}

// TestStrictDecodeJSON_RejectsDuplicateInsideArray — arrays are walked too, so
// an object buried in one cannot hide a duplicate.
func TestStrictDecodeJSON_RejectsDuplicateInsideArray(t *testing.T) {
	body := `[{"a":1,"a":2}]`
	if err := rejectDuplicateJSONKeys([]byte(body)); err == nil {
		t.Fatal("duplicate key inside an array accepted")
	}
}

func TestStrictDecodeJSON_RejectsUnknownField(t *testing.T) {
	body := `{"name":"n","count":1,"optional":null,"nested":{"alpha":"a","beta":2},"aad_b64":"x"}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if !strings.Contains(err.Error(), "aad_b64") {
		t.Fatalf("error must name the unknown field, got %q", err.Error())
	}
}

func TestStrictDecodeJSON_RejectsUnknownNestedField(t *testing.T) {
	body := `{"name":"n","count":1,"optional":null,"nested":{"alpha":"a","beta":2,"gamma":3}}`
	var out strictOuter
	if err := strictDecodeJSON([]byte(body), &out); err == nil {
		t.Fatal("unknown nested field accepted")
	}
}

func TestStrictDecodeJSON_RejectsMissingRequiredField(t *testing.T) {
	body := `{"name":"n","optional":null,"nested":{"alpha":"a","beta":2}}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("missing required field accepted")
	}
	if !strings.Contains(err.Error(), "count") {
		t.Fatalf("error must name the missing field, got %q", err.Error())
	}
}

// TestStrictDecodeJSON_RejectsMissingNullableKey — a nullable field is still a
// required key. Omitting it must not read as null.
func TestStrictDecodeJSON_RejectsMissingNullableKey(t *testing.T) {
	body := `{"name":"n","count":1,"nested":{"alpha":"a","beta":2}}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("missing nullable key accepted")
	}
	if !strings.Contains(err.Error(), "optional") {
		t.Fatalf("error must name the missing field, got %q", err.Error())
	}
}

func TestStrictDecodeJSON_RejectsMissingNestedField(t *testing.T) {
	body := `{"name":"n","count":1,"optional":null,"nested":{"alpha":"a"}}`
	var out strictOuter
	err := strictDecodeJSON([]byte(body), &out)
	if err == nil {
		t.Fatal("missing nested field accepted")
	}
	if !strings.Contains(err.Error(), "beta") {
		t.Fatalf("error must name the missing field, got %q", err.Error())
	}
}

func TestStrictDecodeJSON_RejectsTrailingContent(t *testing.T) {
	body := strictValidJSON() + `{"name":"other"}`
	var out strictOuter
	if err := strictDecodeJSON([]byte(body), &out); err == nil {
		t.Fatal("trailing JSON content accepted")
	}
}

func TestStrictDecodeJSON_RejectsEmptyAndNonObject(t *testing.T) {
	for _, body := range []string{"", "null", "[]", `"text"`, "{", `{"name":}`} {
		var out strictOuter
		if err := strictDecodeJSON([]byte(body), &out); err == nil {
			t.Fatalf("payload %q accepted", body)
		}
	}
}
