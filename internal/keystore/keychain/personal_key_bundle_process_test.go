//go:build darwin || linux || windows

package keychain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
)

const personalKeyBundleHelperMode = "DRAGPASS_TEST_KEY_BUNDLE_HELPER"

type personalKeyBundleChildResult struct {
	output string
	err    error
}

func TestPersonalKeyBundleProcessHelper(t *testing.T) {
	mode := os.Getenv(personalKeyBundleHelperMode)
	if mode == "" {
		return
	}

	readyPath := os.Getenv("DRAGPASS_TEST_KEY_BUNDLE_READY")
	if mode == "holder" {
		unlock, err := acquirePersonalKeyBundleProcessLock()
		if err != nil {
			fmt.Printf("error: acquire lock: %v", err)
			return
		}
		defer unlock()
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			fmt.Printf("error: signal holder: %v", err)
			return
		}
		if err := waitForKeyBundleTestFile(os.Getenv("DRAGPASS_TEST_KEY_BUNDLE_RELEASE")); err != nil {
			fmt.Printf("error: wait for release: %v", err)
			return
		}
		fmt.Print("released")
		return
	}

	if err := LoadE2EKeyringFile(os.Getenv(e2eKeyringFileEnvVar)); err != nil {
		fmt.Printf("error: load shared store: %v", err)
		return
	}
	if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
		fmt.Printf("error: signal rotation: %v", err)
		return
	}
	err := CommitPersonalKeyBundleRotation(
		KeyringSecretStore{},
		"old-device",
		"old-wrapped",
		"new-device-"+mode,
		"new-wrapped-"+mode,
	)
	if err == nil {
		fmt.Printf("success:%s", mode)
		return
	}
	if strings.Contains(err.Error(), "active device key changed during rotation") {
		fmt.Printf("rejected:%s", mode)
		return
	}
	fmt.Printf("error:%s:%v", mode, err)
}

func TestPersonalKeyBundleRotationSerializesAcrossProcesses(t *testing.T) {
	tempDir := t.TempDir()
	sharedStorePath := filepath.Join(tempDir, "keyring.json")
	initial := map[string]string{
		e2eKey(config.Service, config.DeviceKey):                "old-device",
		e2eKey(config.Service, config.PersonalDeviceWrappedDEK): "old-wrapped",
	}
	writeKeyBundleTestStore(t, sharedStorePath, initial)

	holderReady := filepath.Join(tempDir, "holder-ready")
	releaseHolder := filepath.Join(tempDir, "release-holder")
	holder, holderDone := startKeyBundleTestChild(t, tempDir, "holder", holderReady, sharedStorePath,
		"DRAGPASS_TEST_KEY_BUNDLE_RELEASE="+releaseHolder)
	waitForKeyBundleTestReady(t, holderReady)

	firstReady := filepath.Join(tempDir, "first-ready")
	secondReady := filepath.Join(tempDir, "second-ready")
	first, firstDone := startKeyBundleTestChild(t, tempDir, "first", firstReady, sharedStorePath)
	second, secondDone := startKeyBundleTestChild(t, tempDir, "second", secondReady, sharedStorePath)
	waitForKeyBundleTestReady(t, firstReady)
	waitForKeyBundleTestReady(t, secondReady)

	assertKeyBundleChildBlocked(t, firstDone)
	assertKeyBundleChildBlocked(t, secondDone)
	if err := os.WriteFile(releaseHolder, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}

	holderResult := waitForKeyBundleTestChild(t, holder, holderDone)
	if holderResult.err != nil || !strings.Contains(holderResult.output, "released") {
		t.Fatalf("holder result: output=%q err=%v", holderResult.output, holderResult.err)
	}
	firstResult := waitForKeyBundleTestChild(t, first, firstDone)
	secondResult := waitForKeyBundleTestChild(t, second, secondDone)
	results := []personalKeyBundleChildResult{firstResult, secondResult}

	winner := ""
	successes := 0
	rejections := 0
	for _, result := range results {
		if result.err != nil || strings.Contains(result.output, "error:") {
			t.Fatalf("rotation child failed: output=%q err=%v", result.output, result.err)
		}
		switch {
		case strings.Contains(result.output, "success:first"):
			winner = "first"
			successes++
		case strings.Contains(result.output, "success:second"):
			winner = "second"
			successes++
		case strings.Contains(result.output, "rejected:"):
			rejections++
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("expected one success and one rejection, got %#v", results)
	}

	finalStore := readKeyBundleTestStore(t, sharedStorePath)
	if got := finalStore[e2eKey(config.Service, config.DeviceKey)]; got != "new-device-"+winner {
		t.Fatalf("final device key = %q, winner = %q", got, winner)
	}
	if got := finalStore[e2eKey(config.Service, config.PersonalDeviceWrappedDEK)]; got != "new-wrapped-"+winner {
		t.Fatalf("final wrapped DEK = %q, winner = %q", got, winner)
	}
	if _, ok := finalStore[e2eKey(config.Service, config.PendingPersonalKeyBundle)]; ok {
		t.Fatal("rotation journal remains after serialized commits")
	}
}

func startKeyBundleTestChild(
	t *testing.T,
	tempDir, mode, readyPath, sharedStorePath string,
	extraEnv ...string,
) (*exec.Cmd, <-chan personalKeyBundleChildResult) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPersonalKeyBundleProcessHelper$")
	cmd.Env = append(os.Environ(),
		personalKeyBundleHelperMode+"="+mode,
		"DRAGPASS_TEST_KEY_BUNDLE_READY="+readyPath,
		e2eKeyringFileEnvVar+"="+sharedStorePath,
		"HOME="+tempDir,
		"XDG_CONFIG_HOME="+filepath.Join(tempDir, "config"),
		"APPDATA="+filepath.Join(tempDir, "appdata"),
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
	})
	done := make(chan personalKeyBundleChildResult, 1)
	go func() {
		err := cmd.Wait()
		done <- personalKeyBundleChildResult{output: output.String(), err: err}
	}()
	return cmd, done
}

func assertKeyBundleChildBlocked(t *testing.T, done <-chan personalKeyBundleChildResult) {
	t.Helper()
	select {
	case result := <-done:
		t.Fatalf("rotation child bypassed process lock: output=%q err=%v", result.output, result.err)
	case <-time.After(150 * time.Millisecond):
	}
}

func waitForKeyBundleTestChild(
	t *testing.T,
	cmd *exec.Cmd,
	done <-chan personalKeyBundleChildResult,
) personalKeyBundleChildResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timed out waiting for key bundle test child")
		return personalKeyBundleChildResult{}
	}
}

func waitForKeyBundleTestReady(t *testing.T, path string) {
	t.Helper()
	if err := waitForKeyBundleTestFile(path); err != nil {
		t.Fatal(err)
	}
}

func waitForKeyBundleTestFile(path string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func writeKeyBundleTestStore(t *testing.T, path string, store map[string]string) {
	t.Helper()
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readKeyBundleTestStore(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var store map[string]string
	if err := json.Unmarshal(raw, &store); err != nil {
		t.Fatal(err)
	}
	return store
}
