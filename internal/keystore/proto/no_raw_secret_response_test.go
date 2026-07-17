// no_raw_secret_response_test.go — registry-wide guard: no dispatcher action
// may return raw secret key material in its response envelope.
//
// Every registered Keeper action returns one of the proto *ResponseData structs
// defined in this package. This test AST-scans the whole package, walks each
// *ResponseData struct's JSON field names (recursing into nested proto structs),
// and flags any field whose name matches a raw-secret pattern: raw key bytes,
// a bare unwrapped DEK, plaintext, or a private-key PEM. A match must be listed
// in rawSecretResponseCarveOuts with an English rationale, otherwise the test
// fails — so a new action that accidentally puts a raw DEK in its response is
// caught at CI time instead of shipping. Encrypted / wrapped key material is
// ciphertext and is explicitly treated as safe to return.
package proto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// rawSecretResponseCarveOuts lists "<ResponseType>.<json_field>" entries that
// legitimately carry raw secret material across IPC. Each entry needs an
// English rationale. Keep this list as small as possible.
//
// This map is intentionally empty: no Keeper action returns raw secret key
// material over IPC. The last carve-out (unwrapgroupdek's group_dek_b64) was
// removed together with the unwrapgroupdek / group_session_open_with_raw
// actions — all group crypto is now handle-based.
var rawSecretResponseCarveOuts = map[string]string{}

var rawTokenRe = regexp.MustCompile(`(^|_)raw($|_)`)

// isRawSecretField reports whether a JSON field name denotes raw secret key
// material that must not cross the IPC boundary. Ciphertext / wrapped-key
// fields (encrypted_* / wrapped_*) are safe and explicitly excluded.
func isRawSecretField(jsonName string) bool {
	n := strings.ToLower(jsonName)
	if strings.Contains(n, "encrypted") || strings.Contains(n, "wrapped") {
		return false // ciphertext / wrapped key material is safe to return
	}
	switch {
	case strings.Contains(n, "plaintext"):
		return true
	case rawTokenRe.MatchString(n): // e.g. item_dek_raw_b64
		return true
	case strings.HasSuffix(n, "_dek_b64"): // bare unwrapped DEK bytes, e.g. group_dek_b64
		return true
	case strings.Contains(n, "private") && strings.Contains(n, "pem"):
		return true
	default:
		return false
	}
}

type fieldRef struct {
	owner string // struct that declares the field
	json  string // the field's JSON name
}

func TestNoRawSecretInResponseTypes(t *testing.T) {
	structs := parseProtoStructs(t)

	seenCarveOut := map[string]bool{}
	reported := map[string]bool{}
	responseTypes := 0

	for name, st := range structs {
		if !strings.HasSuffix(name, "ResponseData") {
			continue
		}
		responseTypes++
		for _, f := range collectJSONFields(structs, name, st) {
			if !isRawSecretField(f.json) {
				continue
			}
			key := f.owner + "." + f.json
			if _, ok := rawSecretResponseCarveOuts[key]; ok {
				seenCarveOut[key] = true
				continue
			}
			if reported[key] {
				continue
			}
			reported[key] = true
			t.Errorf("response type %s carries raw-secret field %q (declared on %s); "+
				"raw key material must not cross IPC. If this is intentional, add %q "+
				"to rawSecretResponseCarveOuts with an English rationale.",
				name, f.json, f.owner, key)
		}
	}

	if responseTypes == 0 {
		t.Fatal("scanned 0 *ResponseData types — parser/discovery is broken")
	}

	// Keep the carve-out list honest: a stale entry means the raw return was
	// removed and the exception should be deleted.
	for key := range rawSecretResponseCarveOuts {
		if !seenCarveOut[key] {
			t.Errorf("stale carve-out %q — no response field matched it; "+
				"remove it from rawSecretResponseCarveOuts.", key)
		}
	}
}

// collectJSONFields returns every JSON field reachable from the named response
// struct, recursing into nested locally-defined struct types. Recursion is
// guarded against cycles by struct name.
func collectJSONFields(structs map[string]*ast.StructType, typeName string, st *ast.StructType) []fieldRef {
	var out []fieldRef
	seen := map[string]bool{}

	var walk func(tn string, s *ast.StructType)
	walk = func(tn string, s *ast.StructType) {
		if seen[tn] {
			return
		}
		seen[tn] = true
		for _, field := range s.Fields.List {
			if jsonName := jsonFieldName(field); jsonName != "" && jsonName != "-" {
				out = append(out, fieldRef{owner: tn, json: jsonName})
			}
			if elem := baseTypeName(field.Type); elem != "" {
				if child, ok := structs[elem]; ok {
					walk(elem, child)
				}
			}
		}
	}
	walk(typeName, st)
	return out
}

// jsonFieldName extracts the JSON name from a struct field's tag, or "" if the
// field is untagged.
func jsonFieldName(field *ast.Field) string {
	if field.Tag == nil {
		return ""
	}
	tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
	name := tag.Get("json")
	if name == "" {
		return ""
	}
	return strings.Split(name, ",")[0]
}

// baseTypeName unwraps pointer / slice / map wrappers to the underlying named
// type. Returns "" for qualified (imported) or anonymous types.
func baseTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.ArrayType:
		return baseTypeName(t.Elt)
	case *ast.MapType:
		return baseTypeName(t.Value)
	default:
		return ""
	}
}

// parseProtoStructs parses every non-test .go file in this package's directory
// and returns a map of struct type name → its AST.
func parseProtoStructs(t *testing.T) map[string]*ast.StructType {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read proto dir: %v", err)
	}

	fset := token.NewFileSet()
	structs := map[string]*ast.StructType{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if st, ok := ts.Type.(*ast.StructType); ok {
					structs[ts.Name.Name] = st
				}
			}
		}
	}
	return structs
}
