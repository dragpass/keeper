package keytransparency

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func writeTrustFile(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	_, logPublic, err := note.GenerateKey(rand.Reader, "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]string, 3)
	for i := range witnesses {
		_, public, err := note.GenerateKey(rand.Reader, string(rune('a'+i))+".witness")
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i] = public
	}
	config := map[string]any{
		"origin":                     "dragpass.test/log",
		"log_verifier":               logPublic,
		"witness_verifiers":          witnesses,
		"quorum":                     2,
		"max_checkpoint_age_seconds": 86400,
		"future_skew_seconds":        300,
	}
	if mutate != nil {
		mutate(config)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGateFromEnvWithoutTrustFileKeepsTheOldRules(t *testing.T) {
	t.Setenv(TrustConfigEnv, "")
	gate := LoadGateFromEnv()
	if gate.Required() || gate.Trust != nil || gate.ConfigErr != nil {
		t.Fatalf("gate = %+v, want nothing required", gate)
	}
}

func TestLoadGateFromEnvWithValidTrustFileRequiresTransparency(t *testing.T) {
	t.Setenv(TrustConfigEnv, writeTrustFile(t, nil))
	gate := LoadGateFromEnv()
	if !gate.Required() || gate.Trust == nil || gate.ConfigErr != nil {
		t.Fatalf("gate = %+v, want a loaded trust", gate)
	}
	if gate.Trust.Quorum != 2 || len(gate.Trust.WitnessVerifiers) != 3 {
		t.Fatalf("trust = %+v, want 2-of-3", gate.Trust)
	}
}

// Witness independence is not something a trust file can claim: the Keeper
// cannot check who runs the witnesses, and a flag that nothing verifies would
// let a label read "independent" on the server's own log. Until a real
// independent witness exists the key is not part of the schema, so a file
// carrying it, either value, is invalid and fails closed like any other
// unknown field.
func TestLoadGateFromEnvRejectsSelfDeclaredWitnessIndependence(t *testing.T) {
	for _, declared := range []bool{true, false} {
		t.Setenv(TrustConfigEnv, writeTrustFile(t, func(c map[string]any) { c["independent_witnesses"] = declared }))
		gate := LoadGateFromEnv()
		if gate.Trust != nil || !errors.Is(gate.ConfigErr, ErrTrustInvalid) || !gate.Required() {
			t.Fatalf("independent_witnesses=%v: gate = %+v, want fail-closed invalid trust", declared, gate)
		}
	}
}

func TestLoadGateFromEnvWithUnusableTrustFileFailsClosed(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing file":    filepath.Join(t.TempDir(), "absent.json"),
		"malformed json":  garbage,
		"one witness":     writeTrustFile(t, func(c map[string]any) { c["witness_verifiers"] = c["witness_verifiers"].([]string)[:1] }),
		"unknown field":   writeTrustFile(t, func(c map[string]any) { c["quorum_override"] = 1 }),
		"bad log key":     writeTrustFile(t, func(c map[string]any) { c["log_verifier"] = "not-a-key" }),
		"directory given": t.TempDir(),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(TrustConfigEnv, path)
			gate := LoadGateFromEnv()
			if !gate.Required() || gate.Trust != nil || !errors.Is(gate.ConfigErr, ErrTrustInvalid) {
				t.Fatalf("gate = %+v, want required with ErrTrustInvalid", gate)
			}
		})
	}
}
