//go:build darwin

package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestLaunchAgentContainsUserServiceConfiguration(t *testing.T) {
	content, err := marshalLaunchAgent("/Applications/DragPass & Keeper/dragpass-keeper", "/Users/test/Library/Logs/DragPass/app-service.log", "/Users/test/DragPass trust.json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if err := xml.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("invalid launchd plist XML: %v", err)
	}
	text := string(content)
	for _, expected := range []string{
		"io.dragpass.keeper.app-service", "ProgramArguments", "--app-service",
		"RunAtLoad", "KeepAlive", "&amp; Keeper", "StandardErrorPath",
		"DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE", "DragPass trust.json",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("LaunchAgent does not contain %q", expected)
		}
	}
}
