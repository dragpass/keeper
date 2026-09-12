// strict_json.go — the decoder the message display actions use instead of
// json.Unmarshal.
//
// The dispatcher's shared `process` helper decodes with plain json.Unmarshal,
// which silently drops unknown fields, silently keeps the *last* of a duplicate
// key, and silently leaves a missing field at its zero value. For most actions
// that is fine — the field is either validated or unused. For a request whose
// fields are bound into a server signature it is not: `{"dek_version":7,
// "dek_version":9}` would verify against one value and decrypt under another,
// and a dropped `audit_table_id` would turn an audit message into a normal one
// without anyone noticing.
//
// So the message actions decode through strictDecodeJSON, which refuses all
// three, at every depth. Nothing else in the repo needs this yet; when a second
// caller appears, this is the file to reuse rather than copy.

package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// strictDecodeJSON decodes exactly one JSON object into v, rejecting duplicate
// keys at any depth, unknown fields, trailing content, and any required key the
// object left out.
//
// "Required" means every field of v (recursively, through nested structs) whose
// json tag is neither "-" nor marked omitempty. A nullable field is still a
// required *key*: `"audit_table_id": null` is accepted, omitting it is not.
func strictDecodeJSON(data []byte, v any) error {
	if len(data) == 0 {
		return errors.New("payload must not be empty")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON content")
	}
	return requireJSONObjectKeys(data, v)
}

// rejectDuplicateJSONKeys walks the document token by token and fails on the
// second occurrence of any key within the same object. encoding/json has no
// option for this: json.Unmarshal takes the last value and reports nothing, so
// the only way to see a duplicate is to look at the tokens.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if err := walkJSONValue(dec, tok); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON content")
	}
	return nil
}

// walkJSONValue consumes the value that starts at tok. Scalars are already
// complete; objects and arrays are walked to their closing delimiter.
func walkJSONValue(dec *json.Decoder, tok json.Token) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar: string, number, bool, null
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			if end, ok := keyTok.(json.Delim); ok && end == '}' {
				return nil
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("malformed JSON object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			valueTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(dec, valueTok); err != nil {
				return err
			}
		}
	case '[':
		for {
			itemTok, err := dec.Token()
			if err != nil {
				return err
			}
			if end, ok := itemTok.(json.Delim); ok && end == ']' {
				return nil
			}
			if err := walkJSONValue(dec, itemTok); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("unexpected JSON delimiter %q", delim)
}

// requireJSONObjectKeys checks that data carries every key the shape declares
// as required, recursing into nested struct fields with their own sub-objects.
//
// This is the half DisallowUnknownFields does not cover: it catches the extra
// key, never the missing one.
func requireJSONObjectKeys(data []byte, shape any) error {
	t := reflect.TypeOf(shape)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return errors.New("payload must be a JSON object")
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name, required := requiredJSONFieldName(field)
		if !required {
			continue
		}
		raw, present := object[name]
		if !present {
			return fmt.Errorf("missing required field %q", name)
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() != reflect.Struct {
			continue
		}
		if err := requireJSONObjectKeys(raw, reflect.New(fieldType).Elem().Interface()); err != nil {
			return err
		}
	}
	return nil
}

// requiredJSONFieldName returns a struct field's JSON key and whether the wire
// contract requires it. Unexported, untagged, "-" and omitempty fields are not
// required.
func requiredJSONFieldName(field reflect.StructField) (string, bool) {
	if !field.IsExported() {
		return "", false
	}
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return "", false
	}
	parts := strings.Split(tag, ",")
	if parts[0] == "" || parts[0] == "-" {
		return "", false
	}
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			return "", false
		}
	}
	return parts[0], true
}
