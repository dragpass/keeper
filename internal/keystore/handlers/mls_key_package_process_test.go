//go:build darwin || linux || windows

// The KeyPackage race across two Keeper processes: one generates, the other
// promotes a staged rotation. Each child is this test binary running one
// handler against keychain.KeyringSecretStore, so WithMLSLeafLock takes the
// real cross-process file lock, over the shared mock keyring file that
// mls_leaf_process_test.go uses.
package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const (
	kpProcessHelperMode = "DRAGPASS_TEST_MLS_KP_HELPER"
	kpProcessReachedEnv = "DRAGPASS_TEST_MLS_KP_REACHED"
	kpProcessReleaseEnv = "DRAGPASS_TEST_MLS_KP_RELEASE"
	kpProcessGoEnv      = "DRAGPASS_TEST_MLS_KP_GO"
	kpProcessResult     = "result:"
)

// parkingKeyringStore is poolWriteBarrier for a child process: the first seal
// key read signals the parent through a file and waits for another.
type parkingKeyringStore struct {
	keychain.KeyringSecretStore
	parked         bool
	activeAtResume string
}

func (s *parkingKeyringStore) Get(service, account string) (string, error) {
	if strings.HasPrefix(account, config.ChatStateSealKeyPrefix) && !s.parked {
		s.parked = true
		if err := os.WriteFile(os.Getenv(kpProcessReachedEnv), []byte("reached"), 0o600); err != nil {
			return "", err
		}
		if err := waitForLeafProcessFile(os.Getenv(kpProcessReleaseEnv)); err != nil {
			return "", err
		}
		s.activeAtResume = activeLeafFingerprint(s.KeyringSecretStore)
	}
	return s.KeyringSecretStore.Get(service, account)
}

func TestMLSKeyPackageProcessHelper(t *testing.T) {
	mode := os.Getenv(kpProcessHelperMode)
	if mode == "" {
		return
	}
	keyring.MockInit()
	if err := keychain.LoadE2EKeyringFile(os.Getenv(leafProcessStoreEnv)); err != nil {
		fmt.Printf("error: load shared store: %v", err)
		return
	}
	deps := Deps{
		Logger:            logger.NewMemoryLogger(),
		Store:             keychain.KeyringSecretStore{},
		ServerKeyVerifier: verifier.AlwaysOKVerifier{},
	}
	switch mode {
	case "stage":
		first := enrollLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
		second := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
		out, _ := json.Marshal([]proto.MLSLeafDeclaration{first, second})
		fmt.Printf("%s%s\n", kpProcessResult, out)
	case "generate":
		store := &parkingKeyringStore{}
		deps.Store = store
		resp := HandleMLSKeyPackageGenerate(deps, proto.MLSKeyPackageGenerateRequest{
			ChallengeToken: keyPackageChallengeToken(leafTestAccountID, leafTestDeviceID,
				time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds),
			ServerSignature: "any", AccountID: leafTestAccountID, DeviceID: leafTestDeviceID, Count: 2,
		})
		if !resp.Success {
			fmt.Printf("error: generate: %s", resp.Error)
			return
		}
		data := resp.Data.(proto.MLSKeyPackageGenerateResponseData)
		out, _ := json.Marshal(struct {
			Data           proto.MLSKeyPackageGenerateResponseData
			ActiveAtResume string
		}{data, store.activeAtResume})
		fmt.Printf("%s%s\n", kpProcessResult, out)
	case "promote":
		if err := waitForLeafProcessFile(os.Getenv(kpProcessGoEnv)); err != nil {
			fmt.Printf("error: wait for go: %v", err)
			return
		}
		pending, _, err := keychain.GetMLSLeafPending(deps.Store)
		if err != nil {
			fmt.Printf("error: pending: %v", err)
			return
		}
		decl, err := storedMLSLeafDeclaration(pending)
		if err != nil {
			fmt.Printf("error: pending declaration: %v", err)
			return
		}
		resp := HandleMLSLeafPromote(deps, acceptanceFor(decl))
		if !resp.Success {
			fmt.Printf("error: promote: %s", resp.Error)
			return
		}
		fmt.Printf("%s%t\n", kpProcessResult, resp.Data.(proto.MLSLeafPromoteResponseData).Promoted)
	}
}

func TestMLSKeyPackageGenerate_TwoProcessesAPromoteWaitsForTheGeneration(t *testing.T) {
	if !mls.Available() {
		t.Skip("key packages need the MLS library")
	}
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
	reached := filepath.Join(tempDir, "reached")
	release := filepath.Join(tempDir, "release")
	goPath := filepath.Join(tempDir, "go")
	env := []string{
		leafProcessStoreEnv + "=" + storePath,
		chatstate.RootEnvVar + "=" + filepath.Join(tempDir, "chat-state"),
		kpProcessReachedEnv + "=" + reached,
		kpProcessReleaseEnv + "=" + release,
		kpProcessGoEnv + "=" + goPath,
		"HOME=" + tempDir,
		"XDG_CONFIG_HOME=" + filepath.Join(tempDir, "config"),
		"APPDATA=" + filepath.Join(tempDir, "appdata"),
	}
	wait := func(done <-chan string, what string) string {
		t.Helper()
		select {
		case out := <-done:
			return out
		case <-time.After(20 * time.Second):
			t.Fatalf("the %s child did not finish", what)
			return ""
		}
	}

	var decls []proto.MLSLeafDeclaration
	if out := wait(startKeyPackageProcessChild(t, "stage", env), "stage"); json.Unmarshal([]byte(out), &decls) != nil || len(decls) != 2 {
		t.Fatalf("stage child: %q", out)
	}
	first, second := decls[0], decls[1]

	generated := startKeyPackageProcessChild(t, "generate", env)
	promoted := startKeyPackageProcessChild(t, "promote", env)
	if err := waitForLeafProcessFile(reached); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goPath, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	// With the lock the promote child blocks on the file lock and this wait is
	// only ever spent. Without it the promote finishes well inside.
	var early string
	select {
	case early = <-promoted:
	case <-time.After(time.Second):
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}

	var gen struct {
		Data           proto.MLSKeyPackageGenerateResponseData
		ActiveAtResume string
	}
	if out := wait(generated, "generate"); json.Unmarshal([]byte(out), &gen) != nil {
		t.Fatalf("generate child: %q", out)
	}
	promote := early
	if promote == "" {
		promote = wait(promoted, "promote")
	}
	if ok, err := strconv.ParseBool(promote); err != nil || !ok {
		t.Fatalf("promote child: %q", promote)
	}
	if gen.ActiveAtResume != gen.Data.LeafSignatureKeyFingerprint {
		t.Fatalf("the pool was written for leaf %s while leaf %s was active",
			gen.Data.LeafSignatureKeyFingerprint, gen.ActiveAtResume)
	}
	assertKeyPackagesAreFor(t, gen.Data, first, second)

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var final map[string]string
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}
	var active keychain.MLSLeafKey
	if err := json.Unmarshal([]byte(final[config.Service+"|"+config.MLSLeafSignatureKey]), &active); err != nil {
		t.Fatalf("active slot: %v", err)
	}
	if base64.StdEncoding.EncodeToString(active.PublicKey) != second.SignatureKey {
		t.Fatal("the promote did not take effect after the generation")
	}
}

// startKeyPackageProcessChild runs one helper mode and yields what it printed
// after the result marker, or its whole output if there is none.
func startKeyPackageProcessChild(t *testing.T, mode string, env []string) <-chan string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMLSKeyPackageProcessHelper$")
	cmd.Env = append(append(os.Environ(), kpProcessHelperMode+"="+mode), env...)
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
		if _, rest, ok := strings.Cut(out, kpProcessResult); ok {
			out, _, _ = strings.Cut(rest, "\n")
		}
		done <- out
	}()
	return done
}
