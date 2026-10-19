package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/version"
)

func TestVersionCommandPrintsTheBuildVersion(t *testing.T) {
	var out bytes.Buffer
	printVersion(&out)
	if !strings.HasPrefix(out.String(), "version: "+version.Version+"\n") {
		t.Fatalf("unexpected version output %q", out.String())
	}
}
