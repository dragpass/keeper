//go:build darwin

package service

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

// launchd's XPC plist parser rejects <true></true> with "Invalid property list"
// (bootstrap then fails with EIO) even though plutil -lint accepts it.
func TestLaunchAgentBooleansAreSelfClosing(t *testing.T) {
	content, err := marshalLaunchAgent("/usr/local/bin/dragpass-keeper", "/tmp/app-service.log", "")
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, key := range []string{"RunAtLoad", "KeepAlive"} {
		if !regexp.MustCompile(`<key>` + key + `</key>\s*<true/>`).MatchString(text) {
			t.Errorf("%s is not followed by a self-closing <true/>:\n%s", key, text)
		}
	}
	if strings.Contains(text, "</true>") || strings.Contains(text, "</false>") {
		t.Errorf("LaunchAgent contains a boolean end tag:\n%s", text)
	}
}

func TestLaunchAgentGolden(t *testing.T) {
	content, err := marshalLaunchAgent(
		"/Applications/DragPass & <Keeper>/dragpass-keeper",
		"/Users/test/Library/Logs/Drag\"Pass'/app-service.log",
		"/Users/test/trust & <x>.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>io.dragpass.keeper.app-service</string>
    <key>ProgramArguments</key>
    <array>
      <string>/Applications/DragPass &amp; &lt;Keeper&gt;/dragpass-keeper</string>
      <string>--app-service</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE</key>
      <string>/Users/test/trust &amp; &lt;x&gt;.json</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Users/test/Library/Logs/Drag&#34;Pass&#39;/app-service.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/test/Library/Logs/Drag&#34;Pass&#39;/app-service.log</string>
  </dict>
</plist>
`
	if string(content) != want {
		t.Fatalf("LaunchAgent mismatch\n--- got ---\n%s\n--- want ---\n%s", content, want)
	}
}

// TestLaunchAgentBootstrapsInLaunchd loads a generated agent into the real
// per-user launchd domain, so it only runs when DRAGPASS_KEEPER_LAUNCHD_E2E=1
// is set (never in CI). It also checks that the old <true></true> encoding is
// rejected, which pins the reason for the self-closing booleans.
func TestLaunchAgentBootstrapsInLaunchd(t *testing.T) {
	if testing.Short() || os.Getenv("DRAGPASS_KEEPER_LAUNCHD_E2E") != "1" {
		t.Skip("set DRAGPASS_KEEPER_LAUNCHD_E2E=1 to bootstrap a test agent in launchd")
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	dir := t.TempDir()
	label := fmt.Sprintf("io.dragpass.keeper.launchd-test.%d.%d", os.Getpid(), time.Now().UnixNano())
	content, err := renderLaunchAgent(agentDict{
		Label:             label,
		ProgramArguments:  []string{"/usr/bin/true"},
		StandardOutPath:   filepath.Join(dir, "agent.log"),
		StandardErrorPath: filepath.Join(dir, "agent.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := func(name string, plist []byte) error {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, plist, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput()
		if err == nil {
			_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
			return nil
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}

	legacy := []byte(strings.ReplaceAll(string(content), "<true/>", "<true></true>"))
	if err := bootstrap("legacy.plist", legacy); err == nil {
		t.Error("launchd accepted the legacy <true></true> encoding; the regression pin is stale")
	} else {
		t.Logf("legacy encoding rejected as expected: %v", err)
	}
	if err := bootstrap("agent.plist", content); err != nil {
		t.Fatalf("launchd rejected the generated LaunchAgent: %v\n%s", err, content)
	}
}
