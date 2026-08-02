package userpresence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// E2EFileState is test-only plaintext stored under an isolated browser
// profile. Production wiring never constructs this backend.
type E2EFileState struct {
	ShownRecoveryKey string `json:"shown_recovery_key,omitempty"`
}

// E2EFile is a deterministic user-presence backend for headless extension
// tests. The environment contains only this file's path, never secret data.
type E2EFile struct {
	path string
	mu   sync.Mutex
}

func NewE2EFile(path string) *E2EFile {
	return &E2EFile{path: path}
}

func (e *E2EFile) Capabilities() Capabilities {
	return Capabilities{
		Available:       true,
		ShowRecoveryKey: true,
		Backend:         "e2e-file",
	}
}

func (e *E2EFile) readState() (E2EFileState, error) {
	raw, err := os.ReadFile(e.path)
	if err != nil {
		return E2EFileState{}, err
	}
	var state E2EFileState
	if err := json.Unmarshal(raw, &state); err != nil {
		return E2EFileState{}, err
	}
	return state, nil
}

func (e *E2EFile) writeState(state E2EFileState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(e.path, raw, 0o600)
}

func (e *E2EFile) ShowRecoveryKey(ctx context.Context, prompt RecoveryKeyPrompt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if prompt.RecoveryKey == nil {
		return errors.New("recovery key is unavailable")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.readState()
	if err != nil {
		return err
	}
	state.ShownRecoveryKey = string(prompt.RecoveryKey.Bytes())
	return e.writeState(state)
}
