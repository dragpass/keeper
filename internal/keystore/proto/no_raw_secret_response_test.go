// no_raw_secret_response_test.go — registry-wide guards: no dispatcher action
// may carry raw secret key material across the IPC boundary, in either
// direction.
//
// Every registered Keeper action takes one of the proto *Request structs and
// returns one of the *ResponseData structs defined in this package. These tests
// AST-scan the whole package, walk each struct's JSON field names (recursing
// into nested proto structs), and flag any field whose name matches a raw-secret
// pattern: raw key bytes, a bare unwrapped DEK, plaintext, or a private-key PEM.
//
//   - TestNoRawSecretInResponseTypes scans *ResponseData structs. A response
//     must never echo raw secret material back to the JS heap.
//   - TestNoRawSecretInRequestTypes scans *Request structs. This is the guard
//     the removal of wrapgroupdek added: a raw Group DEK cannot exist in the
//     extension JS heap, so no request may accept raw Group DEK / raw key bytes
//     as input either — the only legitimate raw input is encrypt-direction
//     plaintext (see rawSecretRequestCarveOuts).
//
// A match must be listed in the matching carve-out map with an English
// rationale, otherwise the test fails — so a new action that accidentally moves
// a raw DEK across IPC is caught at CI time instead of shipping. Encrypted /
// wrapped key material is ciphertext and is explicitly treated as safe.
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
// The list was empty from 0.0.11 — when unwrapgroupdek's group_dek_b64 went
// away with the action itself — until the Secure Message Overlay reopened it
// with exactly one entry. No raw *key* material is in here and none ever
// should be: the one exception is a decrypted message the user asked to read,
// on its way to the DragPass app's own screen.
//
// The scope of that exception, the exposure it accepts, and the invariants it
// must not widen are approved in dragpass-control-plane
// docs/security/secure-message-overlay-proposed-boundary.md (§4 invariant 3
// names this CI change explicitly). Anything beyond this single response type
// needs that approval re-taken at the wider scope — including reusing the
// action for a ciphertext that is not an AAD-bound message, which the fixed
// message AAD is what prevents.
var rawSecretResponseCarveOuts = map[string]string{
	"GroupDecryptWithAadForAppDisplayResponseData.plaintext_b64": "app-display carve-out: the decrypted secure message is the action's entire output, returned only under a server-signed display permit bound to a one-shot Keeper challenge and opened under a Keeper-built message AAD. Zeroized after encoding, never logged; clipboard actions still return no plaintext. Approved in dragpass-control-plane docs/security/secure-message-overlay-proposed-boundary.md.",
	// Second carve-out: the DragPass chat reveal. It opened in 0.0.30 for the
	// v1 conversation reveal, which 0.0.54 removed; what remains is the chat
	// v2 MLS path. The []string covers the slice element type too.
	// mls_decrypt_batch_for_app_display (0.0.49, design M6.3) returns MLS
	// application messages opened with keys the server never held, so it is
	// gated on the conversation-state permit (decision R2); the added `items`
	// carry metadata only. mls_room_name_open (0.0.52) returns a v2 room's
	// name as the single entry, under a key from the confirmed epoch's MLS
	// exporter and a Keeper-built AAD
	// (dragpass.room.name|1|<conversation_id>|<epoch>). Neither adds a
	// response field or a carve-out entry.
	"MLSDisplayResponseData.plaintext_b64": "chat-display carve-out (0.0.30, v1 reveal removed 0.0.54, MLS since 0.0.49 and 0.0.52): mls_decrypt_batch_for_app_display returns chat v2 MLS application messages as the action's entire output, under the server-signed dragpass.chat.state permit (no read permit: the Keeper opens them with MLS keys the server never held, decision R2), each opened by chatstate.Store.ReceiveBatch with its sender taken from the MLS leaf credential and its declared position checked, or re-read from the sealed local history; items carries that metadata and no plaintext. []string element type is covered here too. Any tag/UTF-8/declaration failure refuses the whole batch with no partial plaintext and nothing written; the one exception is a message this device sent with no sealed local copy, returned as an empty entry with items state own_without_local_copy (0.0.52); since 0.0.53 one whose ciphertext is byte for byte this device's own unbound outbox entry is first bound to its seq and returned from the sealed local history like any other re-read. 0.0.52: mls_room_name_open returns a v2 room name as the single entry, under the same dragpass.chat.state permit, sealed with a key from the confirmed epoch's MLS exporter (label \"dragpass room name\", context conversation_id) and opened under the Keeper-built AAD dragpass.room.name|1|<conversation_id>|<epoch>, only for the confirmed epoch; a tag or UTF-8 failure refuses it with no plaintext and nothing is written. Zeroized after encoding, never logged, not even by length; clipboard actions still return no plaintext. Approved in dragpass-control-plane docs/exec-plans/active/dragpass-chat-v2-mls-integration.md M6.3 and §12.2, and docs/security/threat-model.md §4.10.",
}

// rawSecretRequestCarveOuts lists "<RequestType>.<json_field>" entries whose
// raw secret input is a structurally unavoidable part of the action's contract.
// Each entry needs an English rationale. Keep this list as small as possible.
//
// The only legitimate raw input is encrypt-direction plaintext: an encrypt
// action's entire purpose is to seal caller-supplied plaintext, so the
// plaintext must arrive in the request. It lives only briefly in Keeper memory
// (zeroized after sealing) and never appears in the response or logs. Raw *key*
// material (a raw Group DEK / Item DEK / private key) has no such excuse and
// must never appear here — the removed wrapgroupdek's group_dek_b64 and the
// removed group_session_open_with_raw were exactly such inputs.
var rawSecretRequestCarveOuts = map[string]string{
	"GroupEncryptRequest.plaintext_b64":               "encrypt direction: plaintext to seal under the Group DEK is the action's input; zeroized after sealing, never returned or logged.",
	"GroupEncryptWithAADRequest.plaintext_b64":        "encrypt direction: plaintext to seal under the Group DEK (AAD-bound) is the action's input; zeroized after sealing, never returned or logged.",
	"DEKUnwrapAndEncryptRequest.plaintext_b64":        "encrypt direction: plaintext to seal under the personal DEK is the action's input; zeroized after sealing, never returned or logged.",
	"DEKUnwrapAndEncryptWithAADRequest.plaintext_b64": "encrypt direction: plaintext to seal under the personal DEK (AAD-bound) is the action's input; zeroized after sealing, never returned or logged.",
	"MLSEncryptRequest.plaintext_b64":                 "encrypt direction: the chat v2 message to encrypt as an MLS application message is the action's input; zeroized after sealing, never returned or logged, not even by length.",
	"MLSRoomNameSealRequest.plaintext_b64":            "encrypt direction: the v2 room name to seal under the confirmed epoch's MLS exporter is the action's input; zeroized after sealing, never returned or logged.",
	"MLSGroupCreateRequest.room_name_plaintext_b64":   "encrypt direction: the v2 room name to reseal for the epoch the pending create makes, from its MLS exporter; zeroized after sealing, never returned or logged.",
	"MLSCommitBuildRequest.room_name_plaintext_b64":   "encrypt direction: the v2 room name to reseal for the epoch the pending Commit makes, from its MLS exporter; zeroized after sealing, never returned or logged.",
}

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

func TestNoRawSecretInRequestTypes(t *testing.T) {
	structs := parseProtoStructs(t)

	seenCarveOut := map[string]bool{}
	reported := map[string]bool{}
	requestTypes := 0

	for name, st := range structs {
		if !strings.HasSuffix(name, "Request") {
			continue
		}
		requestTypes++
		for _, f := range collectJSONFields(structs, name, st) {
			if !isRawSecretField(f.json) {
				continue
			}
			key := f.owner + "." + f.json
			if _, ok := rawSecretRequestCarveOuts[key]; ok {
				seenCarveOut[key] = true
				continue
			}
			if reported[key] {
				continue
			}
			reported[key] = true
			t.Errorf("request type %s carries raw-secret field %q (declared on %s); "+
				"raw key material must not cross IPC as input. If this is intentional "+
				"(encrypt-direction plaintext), add %q to rawSecretRequestCarveOuts "+
				"with an English rationale.",
				name, f.json, f.owner, key)
		}
	}

	if requestTypes == 0 {
		t.Fatal("scanned 0 *Request types — parser/discovery is broken")
	}

	// Keep the carve-out list honest: a stale entry means the raw input was
	// removed and the exception should be deleted.
	for key := range rawSecretRequestCarveOuts {
		if !seenCarveOut[key] {
			t.Errorf("stale carve-out %q — no request field matched it; "+
				"remove it from rawSecretRequestCarveOuts.", key)
		}
	}
}

// TestRawSecretResponseCarveOuts_ScopeIsStated — the two tests above catch a
// new raw field and a stale entry, but not a carve-out whose *behavior* grew
// while its rationale stayed where it was. The chat carve-out has grown that
// way more than once (0.0.49 and 0.0.52 added MLS paths with no new entry and
// no new field), so this test pins that the rationale names every path.
func TestRawSecretResponseCarveOuts_ScopeIsStated(t *testing.T) {
	if len(rawSecretResponseCarveOuts) != 2 {
		t.Fatalf("rawSecretResponseCarveOuts has %d entries, want 2 — "+
			"a third plaintext-returning response is a design decision, not a test update.",
			len(rawSecretResponseCarveOuts))
	}

	const chatKey = "MLSDisplayResponseData.plaintext_b64"
	reason, ok := rawSecretResponseCarveOuts[chatKey]
	if !ok {
		t.Fatalf("carve-out %q is missing", chatKey)
	}
	for _, want := range []string{"mls_decrypt_batch_for_app_display", "dragpass.chat.state", "items",
		"own_without_local_copy", "mls_room_name_open", "dragpass.room.name|1|", "MLS exporter"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the chat carve-out rationale does not mention %q — "+
				"every path that returns plaintext through this field must be named "+
				"in the approved scope.", want)
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
