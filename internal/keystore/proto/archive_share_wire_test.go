package proto

import (
	"encoding/json"
	"os"
	"testing"
)

func TestArchiveShareDecisionCanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/archive-share-decision-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Decision  ArchiveShareDecision `json:"decision"`
		Canonical string               `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if got := ArchiveShareDecisionCanonical(vector.Decision); got != vector.Canonical {
		t.Fatal("canonical signing bytes differ from cross-component vector")
	}
}
