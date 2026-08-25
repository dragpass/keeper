//go:build darwin || linux || windows

package keychain

import (
	"bytes"
	"encoding/json"
	"errors"
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

type crashAfterDeviceKeyStore struct {
	KeyringSecretStore
	checkpointPath string
}

func (s crashAfterDeviceKeyStore) Set(service, account, value string) error {
	if err := s.KeyringSecretStore.Set(service, account, value); err != nil {
		return err
	}
	if account == config.DeviceKey && value == "new-device-crash" {
		if err := os.WriteFile(s.checkpointPath, []byte("written"), 0o600); err != nil {
			return err
		}
		time.Sleep(30 * time.Second)
	}
	return nil
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
	if mode == "timeout" {
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			fmt.Printf("error: signal timeout contender: %v", err)
			return
		}
		unlock, err := acquirePersonalKeyBundleProcessLockWithTimeout(150 * time.Millisecond)
		if err == nil {
			unlock()
			fmt.Print("error: timeout contender acquired lock")
			return
		}
		if !errors.Is(err, errPersonalKeyBundleLockTimeout) {
			fmt.Printf("error: unexpected lock failure: %v", err)
			return
		}
		fmt.Print("timeout")
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
	if mode == "recover" {
		deviceKey, err := GetDeviceKey(KeyringSecretStore{})
		if err != nil {
			fmt.Printf("error: recover device key: %v", err)
			return
		}
		wrappedDEK, err := GetPersonalDeviceWrappedDEK(KeyringSecretStore{})
		if err != nil {
			fmt.Printf("error: recover wrapped DEK: %v", err)
			return
		}
		fmt.Printf("recovered:%s:%s", deviceKey, wrappedDEK)
		return
	}
	store := SecretStore(KeyringSecretStore{})
	if mode == "crash" {
		store = crashAfterDeviceKeyStore{
			checkpointPath: os.Getenv("DRAGPASS_TEST_KEY_BUNDLE_CHECKPOINT"),
		}
	}
	err := CommitPersonalKeyBundleRotation(
		store,
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

func TestPersonalKeyBundleProcessLockTimesOut(t *testing.T) {
	tempDir := t.TempDir()
	sharedStorePath := filepath.Join(tempDir, "keyring.json")
	writeKeyBundleTestStore(t, sharedStorePath, map[string]string{})

	holderReady := filepath.Join(tempDir, "holder-ready")
	releaseHolder := filepath.Join(tempDir, "release-holder")
	holder, holderDone := startKeyBundleTestChild(t, tempDir, "holder", holderReady, sharedStorePath,
		"DRAGPASS_TEST_KEY_BUNDLE_RELEASE="+releaseHolder)
	waitForKeyBundleTestReady(t, holderReady)

	timeoutReady := filepath.Join(tempDir, "timeout-ready")
	contender, contenderDone := startKeyBundleTestChild(t, tempDir, "timeout", timeoutReady, sharedStorePath)
	waitForKeyBundleTestReady(t, timeoutReady)
	contenderResult := waitForKeyBundleTestChild(t, contender, contenderDone)
	if contenderResult.err != nil || !strings.Contains(contenderResult.output, "timeout") {
		t.Fatalf("timeout contender result: output=%q err=%v", contenderResult.output, contenderResult.err)
	}

	if err := os.WriteFile(releaseHolder, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	holderResult := waitForKeyBundleTestChild(t, holder, holderDone)
	if holderResult.err != nil || !strings.Contains(holderResult.output, "released") {
		t.Fatalf("holder result: output=%q err=%v", holderResult.output, holderResult.err)
	}
}

func TestPersonalKeyBundleRecoversAfterRotationProcessCrash(t *testing.T) {
	tempDir := t.TempDir()
	sharedStorePath := filepath.Join(tempDir, "keyring.json")
	initial := map[string]string{
		e2eKey(config.Service, config.DeviceKey):                "old-device",
		e2eKey(config.Service, config.PersonalDeviceWrappedDEK): "old-wrapped",
	}
	writeKeyBundleTestStore(t, sharedStorePath, initial)

	crashReady := filepath.Join(tempDir, "crash-ready")
	checkpoint := filepath.Join(tempDir, "device-key-written")
	crashing, crashingDone := startKeyBundleTestChild(
		t,
		tempDir,
		"crash",
		crashReady,
		sharedStorePath,
		"DRAGPASS_TEST_KEY_BUNDLE_CHECKPOINT="+checkpoint,
	)
	waitForKeyBundleTestReady(t, crashReady)
	waitForKeyBundleTestReady(t, checkpoint)
	if err := crashing.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	crashResult := waitForKeyBundleTestChild(t, crashing, crashingDone)
	if crashResult.err == nil {
		t.Fatalf("crashing rotation exited successfully: %q", crashResult.output)
	}

	recoveryReady := filepath.Join(tempDir, "recovery-ready")
	recovery, recoveryDone := startKeyBundleTestChild(t, tempDir, "recover", recoveryReady, sharedStorePath)
	waitForKeyBundleTestReady(t, recoveryReady)
	recoveryResult := waitForKeyBundleTestChild(t, recovery, recoveryDone)
	if recoveryResult.err != nil || !strings.Contains(recoveryResult.output, "recovered:old-device:old-wrapped") {
		t.Fatalf("recovery result: output=%q err=%v", recoveryResult.output, recoveryResult.err)
	}

	finalStore := readKeyBundleTestStore(t, sharedStorePath)
	if got := finalStore[e2eKey(config.Service, config.DeviceKey)]; got != "old-device" {
		t.Fatalf("recovered device key = %q", got)
	}
	if got := finalStore[e2eKey(config.Service, config.PersonalDeviceWrappedDEK)]; got != "old-wrapped" {
		t.Fatalf("recovered wrapped DEK = %q", got)
	}
	if _, ok := finalStore[e2eKey(config.Service, config.PendingPersonalKeyBundle)]; ok {
		t.Fatal("rotation journal remains after crash recovery")
	}
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
