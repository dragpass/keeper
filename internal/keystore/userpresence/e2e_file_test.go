package userpresence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awnumar/memguard"
)

func writeE2EState(t *testing.T, path string, state E2EFileState) {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestE2EFilePromptsAndCapturesRecoveryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presence.json")
	approve := true
	writeE2EState(t, path, E2EFileState{
		Secret:  "login-secret",
		Approve: &approve,
	})
	presence := NewE2EFile(path)

	secret, err := presence.PromptSecret(context.Background(), SecretPrompt{})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Secret.Destroy()
	if got := string(secret.Secret.Bytes()); got != "login-secret" {
		t.Fatalf("secret = %q", got)
	}

	key := memguard.NewBufferFromBytes([]byte("ABCD-EFGH-IJKL-MNOP-QRST-UVWX"))
	defer key.Destroy()
	if err := presence.ShowRecoveryKey(context.Background(), RecoveryKeyPrompt{RecoveryKey: key}); err != nil {
		t.Fatal(err)
	}
	state, err := presence.readState()
	if err != nil {
		t.Fatal(err)
	}
	if state.ShownRecoveryKey != "ABCD-EFGH-IJKL-MNOP-QRST-UVWX" {
		t.Fatalf("shown recovery key = %q", state.ShownRecoveryKey)
	}
	decision, err := presence.Confirm(context.Background(), ConfirmPrompt{})
	if err != nil || decision != DecisionApprove {
		t.Fatalf("decision = %q, err = %v", decision, err)
	}
}
