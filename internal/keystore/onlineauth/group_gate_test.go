package onlineauth

import (
	"testing"
	"time"
)

func groupGateFixture(t *testing.T) (*GroupGate, GroupIdentity, GroupDecision, []byte, *time.Time) {
	t.Helper()
	now := time.Unix(1000, 0)
	gate, err := NewGroup(testVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := GroupIdentity{TokenID: "token", AccountID: "account", DeviceID: "device", OrgID: "org", GroupID: "group",
		DEKVersion: 1, GrantPolicy: "legacy", GrantDigest: "grant-digest", LocalGeneration: 7}
	request := []byte(`{"group_handle":"handle","iv_b64":"iv","ciphertext_b64":"ciphertext"}`)
	challenge, commitment, err := gate.Prepare("group_decrypt_to_clipboard", request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision := GroupDecision{TokenID: id.TokenID, Action: "group_decrypt_to_clipboard", Challenge: challenge, Commitment: commitment,
		AccountID: id.AccountID, DeviceID: id.DeviceID, OrgID: id.OrgID, GroupID: id.GroupID,
		DEKVersion: id.DEKVersion, GrantPolicy: id.GrantPolicy, GrantDigest: id.GrantDigest,
		Client: "extension", SessionStartNanos: 42, IssuedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(15 * time.Second).UnixMilli(),
		ServerKeyVersion: 3, Signature: "signed"}
	return gate, id, decision, request, &now
}

func TestGroupGateConsumesOnlyTheExactCurrentGrantDecision(t *testing.T) {
	gate, id, decision, request, _ := groupGateFixture(t)
	if err := gate.VerifyAndConsume(decision, decision.Action, request, id); err != nil {
		t.Fatal(err)
	}
	if err := gate.VerifyAndConsume(decision, decision.Action, request, id); err == nil {
		t.Fatal("consumed group decision was reused")
	}
}

func TestGroupGateRefusesChangedAuthorityOrRequest(t *testing.T) {
	for name, change := range map[string]func(*GroupGate, *GroupIdentity, *GroupDecision, *[]byte, *time.Time){
		"request": func(_ *GroupGate, _ *GroupIdentity, _ *GroupDecision, request *[]byte, _ *time.Time) {
			*request = []byte("changed")
		},
		"local generation": func(_ *GroupGate, id *GroupIdentity, _ *GroupDecision, _ *[]byte, _ *time.Time) { id.LocalGeneration++ },
		"prepared token":   func(_ *GroupGate, id *GroupIdentity, _ *GroupDecision, _ *[]byte, _ *time.Time) { id.TokenID = "other" },
		"signed token":     func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.TokenID = "other" },
		"account":          func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.AccountID = "other" },
		"device":           func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.DeviceID = "other" },
		"group":            func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.GroupID = "other" },
		"grant": func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) {
			d.GrantDigest = "other"
		},
		"version": func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.DEKVersion++ },
		"channel": func(_ *GroupGate, _ *GroupIdentity, d *GroupDecision, _ *[]byte, _ *time.Time) { d.Client = "mcp" },
		"signature": func(g *GroupGate, _ *GroupIdentity, _ *GroupDecision, _ *[]byte, _ *time.Time) {
			g.verifier = testVerifier{reject: true}
		},
		"expiry": func(_ *GroupGate, _ *GroupIdentity, _ *GroupDecision, _ *[]byte, now *time.Time) {
			*now = now.Add(15 * time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			gate, id, decision, request, now := groupGateFixture(t)
			change(gate, &id, &decision, &request, now)
			if err := gate.VerifyAndConsume(decision, decision.Action, request, id); err == nil {
				t.Fatal("changed online authority was admitted")
			}
		})
	}
}

func TestGroupGateConcurrentDuplicateHasOneAdmission(t *testing.T) {
	gate, id, decision, request, _ := groupGateFixture(t)
	barrier := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() { <-barrier; results <- gate.VerifyAndConsume(decision, decision.Action, request, id) }()
	}
	close(barrier)
	admitted := 0
	for range 2 {
		if <-results == nil {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("duplicate admissions=%d, want 1", admitted)
	}
}
