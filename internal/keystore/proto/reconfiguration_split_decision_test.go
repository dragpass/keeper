package proto

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReconfigurationSplitDecisionGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/reconfiguration_split_decision_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Decision  ReconfigurationSplitDecision `json:"decision"`
		Canonical string                       `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	got, err := vector.Decision.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if got != vector.Canonical {
		t.Fatalf("v2 canonical bytes differ from fixture: %q", got)
	}
}

func TestReconfigurationSplitDecisionRequiresReconfigurationKind(t *testing.T) {
	for _, kind := range []string{"", "activation", "unknown"} {
		d := ReconfigurationSplitDecision{Kind: kind}
		if canonical, err := d.Canonical(); err == nil || canonical != "" {
			t.Errorf("encoded unsupported kind %q", kind)
		}
	}
}
