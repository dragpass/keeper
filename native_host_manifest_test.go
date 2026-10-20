package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/localrpc"
)

// Chrome launches the Native Messaging host only for the extensions its
// manifest names in allowed_origins; Keeper itself never reads the caller
// origin Chrome passes. Every installer (macOS pkg, Linux deb, Windows setup,
// Homebrew cask) writes that manifest, so each must name exactly the DragPass
// Extension, the same one the local RPC trusts as the Extension origin.
func TestNativeHostManifestsAllowOnlyTheDragPassExtension(t *testing.T) {
	want := localrpc.NativeExtensionOrigin + "/"
	extensionID := strings.TrimPrefix(localrpc.NativeExtensionOrigin, "chrome-extension://")
	origin := regexp.MustCompile(`chrome-extension://[^"/\\ ]*/?`)

	makefile := readInstallerFile(t, "Makefile")
	if !strings.Contains(makefile, "EXTENSION_ID := "+extensionID+"\n") {
		t.Fatalf("Makefile EXTENSION_ID is not %s", extensionID)
	}
	manifests := 0
	for _, line := range strings.Split(makefile, "\n") {
		if !strings.Contains(line, `allowed_origins`) {
			continue
		}
		manifests++
		if !strings.Contains(line, `\"chrome-extension://$(EXTENSION_ID)/\"\n  ]`) || strings.Count(line, "chrome-extension://") != 1 {
			t.Fatalf("Makefile manifest allows more than the Extension: %s", line)
		}
	}
	if manifests != 2 {
		t.Fatalf("Makefile writes %d manifests, want 2 (macOS pkg, Linux deb)", manifests)
	}

	for _, file := range []string{"setup.iss", ".goreleaser.yml"} {
		content := readInstallerFile(t, file)
		found := origin.FindAllString(content, -1)
		if len(found) != 1 || found[0] != want {
			t.Fatalf("%s allowed origins = %v, want only %s", file, found, want)
		}
		if !strings.Contains(content, "allowed_origins") {
			t.Fatalf("%s writes no allowed_origins", file)
		}
	}
}

func readInstallerFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}
