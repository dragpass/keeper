package config

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Slot names `make refresh` deletes that are not declared in config.go.
var makefileOnlySlots = []string{
	"chat-runtime-epoch", // internal/keystore/chat_runtime.go
}

// TestMakefileRefreshSlotsMatchConfig keeps the Keychain slot lists of the
// Makefile's refresh target equal to the slots this package declares, so a
// dev reset neither misses a current slot nor carries a removed one.
func TestMakefileRefreshSlotsMatchConfig(t *testing.T) {
	accounts, prefixes := configSlots(t)
	accounts = append(accounts, makefileOnlySlots...)

	makefile, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if got := makeVar(t, string(makefile), "KEEPER_KEYCHAIN_SERVICE"); !slices.Equal(got, []string{Service}) {
		t.Errorf("KEEPER_KEYCHAIN_SERVICE = %v, want %q", got, Service)
	}
	assertSameSet(t, "KEEPER_KEYCHAIN_ACCOUNTS", makeVar(t, string(makefile), "KEEPER_KEYCHAIN_ACCOUNTS"), accounts)
	assertSameSet(t, "KEEPER_KEYCHAIN_ACCOUNT_PREFIXES", makeVar(t, string(makefile), "KEEPER_KEYCHAIN_ACCOUNT_PREFIXES"), prefixes)
}

// configSlots evaluates the string constants of config.go: names ending in
// Prefix are slot prefixes, every other one but Service is a slot name.
func configSlots(t *testing.T) (accounts, prefixes []string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "config.go", nil, 0)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("config", fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("type-check config.go: %v", err)
	}
	for ident, obj := range info.Defs {
		c, ok := obj.(*types.Const)
		if !ok || ident.Name == "Service" || c.Val().Kind() != constant.String {
			continue
		}
		v := constant.StringVal(c.Val())
		if strings.HasSuffix(ident.Name, "Prefix") {
			prefixes = append(prefixes, v)
		} else {
			accounts = append(accounts, v)
		}
	}
	return accounts, prefixes
}

func makeVar(t *testing.T, makefile, name string) []string {
	t.Helper()
	// A Windows checkout (core.autocrlf) ends lines with CRLF.
	joined := strings.ReplaceAll(makefile, "\r\n", "\n")
	joined = strings.ReplaceAll(joined, "\\\n", " ")
	m := regexp.MustCompile(`(?m)^` + name + `\s*:=(.*)$`).FindStringSubmatch(joined)
	if m == nil {
		t.Fatalf("Makefile has no %s", name)
	}
	return strings.Fields(m[1])
}

func assertSameSet(t *testing.T, name string, got, want []string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("%s misses current slot %q", name, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			t.Errorf("%s lists %q, which is not a current slot", name, g)
		}
	}
}

// A Windows checkout with core.autocrlf turns every Makefile line ending into
// CRLF; continuation lines must still join into one value.
func TestMakeVarReadsCRLFContinuationLines(t *testing.T) {
	makefile := "A := \\\r\n\tone two \\\r\n\tthree\r\nB := four\r\n"
	if got, want := makeVar(t, makefile, "A"), []string{"one", "two", "three"}; !slices.Equal(got, want) {
		t.Errorf("A = %q, want %q", got, want)
	}
	if got, want := makeVar(t, makefile, "B"), []string{"four"}; !slices.Equal(got, want) {
		t.Errorf("B = %q, want %q", got, want)
	}
}
