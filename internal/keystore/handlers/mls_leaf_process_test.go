//go:build darwin || linux || windows

// Two Keeper processes declaring at once: the condition the L1 review
// reproduced. Each child is this test binary running one mls_leaf_declare
// against keychain.KeyringSecretStore, which reports itself as the platform
// keyring, so WithMLSLeafLock takes the real cross-process file lock. The
// keyring is go-keyring's mock mirrored through KEEPER_E2E_KEYRING_FILE, the
// same shared store keychain/personal_key_bundle_process_test.go uses.
package handlers

import (
	"bytes"
	"encoding/base64"
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
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const (
	leafProcessHelperMode = "DRAGPASS_TEST_MLS_LEAF_HELPER"
	leafProcessGoEnv      = "DRAGPASS_TEST_MLS_LEAF_GO"
	leafProcessReadyEnv   = "DRAGPASS_TEST_MLS_LEAF_READY"
	leafProcessStoreEnv   = "KEEPER_E2E_KEYRING_FILE"
)

// slowLeafReadStore widens the race: every read of the active slot is held
// for a moment, so two unlocked declares both see it empty before either
// writes. Embedding KeyringSecretStore keeps it the platform keyring as far
// as the lock is concerned.
type slowLeafReadStore struct{ keychain.KeyringSecretStore }

func (s slowLeafReadStore) Get(service, account string) (string, error) {
	value, err := s.KeyringSecretStore.Get(service, account)
	if account == config.MLSLeafSignatureKey {
		time.Sleep(300 * time.Millisecond)
	}
	return value, err
}

func TestMLSLeafProcessHelper(t *testing.T) {
	if os.Getenv(leafProcessHelperMode) == "" {
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
	deps := Deps{
		Logger:            logger.NewMemoryLogger(),
		Store:             slowLeafReadStore{},
		ServerKeyVerifier: verifier.AlwaysOKVerifier{},
	}
	resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	if !resp.Success {
		fmt.Printf("error: declare: %s", resp.Error)
		return
	}
	fmt.Printf("key:%s\n", resp.Data.(proto.MLSLeafDeclareResponseData).SignatureKey)
}

func TestMLSLeafDeclare_TwoProcessesEnrollingAtOnceGetOneKey(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "keyring.json")
	account, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := json.Marshal(map[string]string{
		config.Service + "|" + config.DragPassKeeperPrivateKey: account.PrivateKey,
		config.Service + "|" + config.DragPassKeeperPublicKey:  account.PublicKey,
	})
	if err := os.WriteFile(storePath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	goPath := filepath.Join(tempDir, "go")
	var children []<-chan string
	for i := range 2 {
		ready := filepath.Join(tempDir, fmt.Sprintf("ready-%d", i))
		children = append(children, startLeafProcessChild(t, tempDir, storePath, ready, goPath))
		if err := waitForLeafProcessFile(ready); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(goPath, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}

	var keys []string
	for _, done := range children {
		select {
		case out := <-done:
			key, ok := strings.CutPrefix(out, "key:")
			if !ok {
				t.Fatalf("child failed: %q", out)
			}
			keys = append(keys, key)
		case <-time.After(20 * time.Second):
			t.Fatal("a declaring child did not finish")
		}
	}
	if keys[0] != keys[1] {
		t.Fatal("two Keeper processes enrolling at once returned two different leaf keys")
	}

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var final map[string]string
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}
	if _, ok := final[config.Service+"|"+config.MLSLeafSignatureKey]; ok {
		t.Fatal("an enroll wrote the active slot")
	}
	var pending keychain.MLSLeafKey
	if err := json.Unmarshal([]byte(final[config.Service+"|"+config.MLSLeafSignatureKeyPending]), &pending); err != nil {
		t.Fatalf("pending slot: %v", err)
	}
	if base64.StdEncoding.EncodeToString(pending.PublicKey) != keys[0] {
		t.Fatal("the stored key is not the one both processes returned")
	}
}

func startLeafProcessChild(t *testing.T, tempDir, storePath, ready, goPath string) <-chan string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMLSLeafProcessHelper$")
	cmd.Env = append(os.Environ(),
		leafProcessHelperMode+"=declare",
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
		// The test binary prints its own PASS line after the helper's output.
		out := output.String()
		if i := strings.Index(out, "key:"); i >= 0 {
			out = strings.Fields(out[i:])[0]
		}
		done <- out
	}()
	return done
}

func waitForLeafProcessFile(path string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}
