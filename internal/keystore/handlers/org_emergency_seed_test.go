// org_emergency_seed_test.go — org_emergency_seed_derive answers the seed of
// the golden vector, refuses a malformed org id or code, and writes nothing:
// no Keychain slot, no session handle, no log line with the code or the seed.

package handlers

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type orgEmergencyFixture struct {
	SeedDerivation struct {
		Vectors []struct {
			OrgID   string `json:"org_id"`
			Code    string `json:"code"`
			SeedB64 string `json:"seed_b64"`
		} `json:"vectors"`
		Invalid []struct {
			OrgID  string `json:"org_id"`
			Code   string `json:"code"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	} `json:"seed_derivation"`
}

func loadOrgEmergencyFixture(t *testing.T) orgEmergencyFixture {
	t.Helper()
	raw, err := os.ReadFile("../testdata/org-emergency-code-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f orgEmergencyFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHandleOrgEmergencySeedDeriveAnswersTheGoldenSeedAndStoresNothing(t *testing.T) {
	deps, log, store := newTestDeps(t)
	before := store.Snapshot()
	for _, vec := range loadOrgEmergencyFixture(t).SeedDerivation.Vectors {
		response := HandleOrgEmergencySeedDerive(deps, proto.OrgEmergencySeedDeriveRequest{OrgID: vec.OrgID, Code: vec.Code})
		if !response.Success {
			t.Fatalf("derive %q: %s", vec.Code, response.Error)
		}
		data := response.Data.(proto.OrgEmergencySeedDeriveResponseData)
		if data.Seed != vec.SeedB64 {
			t.Fatalf("seed = %s, want %s", data.Seed, vec.SeedB64)
		}
		encoded, _ := json.Marshal(response)
		if strings.Contains(string(encoded), strings.TrimSpace(vec.Code)) {
			t.Fatal("the answer echoes the code")
		}
		if log.Contains(vec.SeedB64) || log.Contains(strings.TrimSpace(vec.Code)) {
			t.Fatal("the code or seed reached the log")
		}
	}
	if !reflect.DeepEqual(store.Snapshot(), before) {
		t.Fatal("org_emergency_seed_derive wrote to the Keychain")
	}
	if n := deps.RecoveryKeySessions.CloseAll() + deps.RecoverySessions.CloseAll() + deps.GroupSessions.CloseAll(); n != 0 {
		t.Fatalf("org_emergency_seed_derive opened %d session handles", n)
	}
}

func TestHandleOrgEmergencySeedDeriveRefusesMalformedInput(t *testing.T) {
	deps, _, store := newTestDeps(t)
	for _, vec := range loadOrgEmergencyFixture(t).SeedDerivation.Invalid {
		response := HandleOrgEmergencySeedDerive(deps, proto.OrgEmergencySeedDeriveRequest{OrgID: vec.OrgID, Code: vec.Code})
		if response.Success || response.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: %+v", vec.Reason, response)
		}
		if strings.Contains(response.Error, vec.Code) {
			t.Fatalf("%s: the error echoes the code", vec.Reason)
		}
	}
	if response := HandleOrgEmergencySeedDerive(deps, proto.OrgEmergencySeedDeriveRequest{OrgID: "5b0e8b8e-3f4a-4c55-9d2e-0a1b2c3d4e5f"}); response.Success {
		t.Fatal("an empty code derived a seed")
	}
	if store.Size() != 0 {
		t.Fatal("a refused derivation wrote to the Keychain")
	}
}
