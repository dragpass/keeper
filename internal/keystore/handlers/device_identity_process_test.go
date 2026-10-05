//go:build darwin || linux || windows

// Two Keeper processes ensuring the device id at once, each with its own
// candidate (the App's old id and the Extension's old id). Each child is
// this test binary running one device_id_ensure against
// keychain.KeyringSecretStore, so the real cross-process file lock applies;
// the keyring is go-keyring's mock mirrored through KEEPER_E2E_KEYRING_FILE,
// as in mls_leaf_process_test.go.
package handlers

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

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	deviceIDProcessHelperMode = "DRAGPASS_TEST_DEVICE_ID_HELPER"
	deviceIDProcessCandidate  = "DRAGPASS_TEST_DEVICE_ID_CANDIDATE"
)

// slowDeviceIDReadStore holds every read of the device id slot for a moment,
// so two unlocked ensures would both see it empty before either writes.
type slowDeviceIDReadStore struct{ keychain.KeyringSecretStore }

func (s slowDeviceIDReadStore) Get(service, account string) (string, error) {
	value, err := s.KeyringSecretStore.Get(service, account)
	if account == config.DeviceID {
		time.Sleep(300 * time.Millisecond)
	}
	return value, err
}

func TestDeviceIDProcessHelper(t *testing.T) {
	if os.Getenv(deviceIDProcessHelperMode) == "" {
		return
	}
	keyring.MockInit()
	if err := keychain.LoadE2EKeyringFile(os.Getenv(leafProcessStoreEnv)); err != nil {
		fmt.Printf("error: load shared store: %v", err)
		return
	}
	if err := os.WriteFile(os.Getenv(leafProcessReadyEnv), []byte("ready"), 0o600); err != nil {
		fmt.Printf("error: signal ready: %v", err)
		return
	}
	if err := waitForLeafProcessFile(os.Getenv(leafProcessGoEnv)); err != nil {
		fmt.Printf("error: wait for go: %v", err)
		return
	}
	deps := Deps{Logger: testdouble.NewMemoryLogger(), Store: slowDeviceIDReadStore{}}
	resp := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{CandidateDeviceID: os.Getenv(deviceIDProcessCandidate)})
	if !resp.Success {
		fmt.Printf("error: ensure: %s", resp.Error)
		return
	}
	fmt.Printf("key:%s\n", resp.Data.(proto.DeviceIDEnsureResponseData).DeviceID)
}

func TestDeviceIDEnsure_TwoProcessesAtOnceStoreOneID(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "keyring.json")
	if err := os.WriteFile(storePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	goPath := filepath.Join(tempDir, "go")
	candidates := []string{identityTestCandidate, identityTestOther}
	var children []<-chan string
	for i, candidate := range candidates {
		ready := filepath.Join(tempDir, fmt.Sprintf("ready-%d", i))
		children = append(children, startDeviceIDProcessChild(t, tempDir, storePath, ready, goPath, candidate))
		if err := waitForLeafProcessFile(ready); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(goPath, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}

	var ids []string
	for _, done := range children {
		select {
		case out := <-done:
			id, ok := strings.CutPrefix(out, "key:")
			if !ok {
				t.Fatalf("child failed: %q", out)
			}
			ids = append(ids, id)
		case <-time.After(20 * time.Second):
			t.Fatal("an ensuring child did not finish")
		}
	}
	if ids[0] != ids[1] {
		t.Fatalf("two Keeper processes ensuring at once returned %q and %q", ids[0], ids[1])
	}
	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var final map[string]string
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}
	if final[config.Service+"|"+config.DeviceID] != ids[0] {
		t.Fatal("the stored id is not the one both processes returned")
	}
}

func startDeviceIDProcessChild(t *testing.T, tempDir, storePath, ready, goPath, candidate string) <-chan string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeviceIDProcessHelper$")
	cmd.Env = append(os.Environ(),
		deviceIDProcessHelperMode+"=ensure",
		deviceIDProcessCandidate+"="+candidate,
		leafProcessReadyEnv+"="+ready,
		leafProcessGoEnv+"="+goPath,
		leafProcessStoreEnv+"="+storePath,
		"HOME="+tempDir,
		"XDG_CONFIG_HOME="+filepath.Join(tempDir, "config"),
		"APPDATA="+filepath.Join(tempDir, "appdata"),
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	done := make(chan string, 1)
	go func() {
		_ = cmd.Wait()
		out := output.String()
		if i := strings.Index(out, "key:"); i >= 0 {
			out = strings.Fields(out[i:])[0]
		}
		done <- out
	}()
	return done
}
