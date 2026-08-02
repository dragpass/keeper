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

func TestE2EFileCapturesRecoveryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presence.json")
	writeE2EState(t, path, E2EFileState{})
	presence := NewE2EFile(path)

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
}
