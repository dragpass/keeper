//go:build mls && cgo

// key_transparency_gate_process_mls_test.go — the trust file decides, at the
// release binary's boundary, whether an entering leaf needs a log proof.

package killharness

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"golang.org/x/mod/sumdb/note"
)

func writeKeeperTrustFile(t *testing.T) string {
	t.Helper()
	_, logPublic, err := note.GenerateKey(rand.Reader, "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]string, 3)
	for i := range witnesses {
		if _, witnesses[i], err = note.GenerateKey(rand.Reader, string(rune('a'+i))+".witness"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(map[string]any{
		"origin": "dragpass.test/log", "log_verifier": logPublic, "witness_verifiers": witnesses,
		"quorum": 2, "max_checkpoint_age_seconds": 3600, "future_skew_seconds": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKeyTransparencyGateAtTheProcessBoundary(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.json")
	if err := os.WriteFile(garbage, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		trustFile  func(t *testing.T) string
		configured bool
		trustError string
		wantCode   string
	}{
		{name: "absent", trustFile: func(*testing.T) string { return "" }},
		{name: "valid", trustFile: writeKeeperTrustFile, configured: true,
			wantCode: proto.ChatMLSErrorCodeKeyTransparencyUnverified},
		{name: "malformed", trustFile: func(*testing.T) string { return garbage },
			trustError: proto.KeyTransparencyTrustErrorInvalid,
			wantCode:   proto.ChatMLSErrorCodeKeyTransparencyTrustInvalid},
		{name: "unreadable", trustFile: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
			trustError: proto.KeyTransparencyTrustErrorInvalid,
			wantCode:   proto.ChatMLSErrorCodeKeyTransparencyTrustInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alice, bob := newDevice(t, hAlice), newDevice(t, hBob)
			if path := tc.trustFile(t); path != "" {
				alice.env = []string{keytransparency.TrustConfigEnv + "=" + path}
			}
			a, b := alice.start("", 0), bob.start("", 0)

			var status proto.KeyTransparencyStatusResponse
			a.must(proto.ActionKeyTransparencyStatus, proto.KeyTransparencyStatusRequest{}, &status)
			if status.Configured != tc.configured || status.TrustError != tc.trustError || status.IndependentWitnesses {
				t.Fatalf("status = %+v", status)
			}

			a.enrol()
			b.enrol()
			create := proto.MLSGroupCreateRequest{
				Permit: alice.permit(), OrgID: hOrg, ConversationID: hConv,
				ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{b.keyPackage()},
			}
			if tc.wantCode == "" {
				a.must(proto.MLSGroupCreate, create, nil)
				return
			}
			a.refused(proto.MLSGroupCreate, create, tc.wantCode)
		})
	}
}
