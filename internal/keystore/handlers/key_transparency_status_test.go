package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

func testTrust(t *testing.T) *keytransparency.Trust {
	t.Helper()
	_, logPublic, err := note.GenerateKey(rand.Reader, "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	logVerifier, err := note.NewVerifier(logPublic)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]note.Verifier, 3)
	for i := range witnesses {
		_, public, err := note.GenerateKey(rand.Reader, fmt.Sprintf("w%d.witness", i))
		if err != nil {
			t.Fatal(err)
		}
		if witnesses[i], err = formatnote.NewVerifierForCosignatureV1(public); err != nil {
			t.Fatal(err)
		}
	}
	return &keytransparency.Trust{
		Origin: "dragpass.test/log", LogVerifier: logVerifier, WitnessVerifiers: witnesses,
		Quorum: 2, MaxCheckpointAge: time.Hour, FutureSkew: time.Minute,
	}
}

func invalidGate() keytransparency.Gate {
	return keytransparency.Gate{ConfigErr: fmt.Errorf("%w: decode failed", keytransparency.ErrTrustInvalid)}
}

func statusOf(t *testing.T, deps Deps) proto.KeyTransparencyStatusResponse {
	t.Helper()
	response := HandleKeyTransparencyStatus(deps, proto.KeyTransparencyStatusRequest{})
	if !response.Success {
		t.Fatalf("status failed: %s", response.Error)
	}
	status, ok := response.Data.(proto.KeyTransparencyStatusResponse)
	if !ok {
		t.Fatalf("status data = %T", response.Data)
	}
	return status
}

func TestHandleKeyTransparencyStatusReportsTheGate(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	if s := statusOf(t, deps); s.Configured || s.TrustError != "" || s.Anchored || !s.FirstPinEnforced {
		t.Fatalf("absent status = %+v, want unconfigured", s)
	}

	deps.KeyTransparency = keytransparency.Gate{Trust: testTrust(t)}
	if s := statusOf(t, deps); !s.Configured || s.TrustError != "" {
		t.Fatalf("valid status = %+v, want configured", s)
	}

	deps.KeyTransparency = invalidGate()
	if s := statusOf(t, deps); s.Configured || s.TrustError != proto.KeyTransparencyTrustErrorInvalid {
		t.Fatalf("invalid status = %+v, want trust_error=invalid", s)
	}
}

// The status carries no witness-independence field at all, so no client can
// read one and label a server-side record as independent verification.
func TestKeyTransparencyStatusHasNoIndependenceClaim(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.KeyTransparency = keytransparency.Gate{Trust: testTrust(t)}
	encoded, err := json.Marshal(statusOf(t, deps))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "independent") {
		t.Fatalf("status = %s, want no independence field", encoded)
	}
}

// A pinned peer rotates with a valid signed chain but no log proof. With no
// trust file the old rules advance the pin; with a trust file the change needs
// a proof; with a broken trust file it is refused rather than let through.
func TestPeerKeyChainEvaluateFollowsTheKeyTransparencyGate(t *testing.T) {
	cases := []struct {
		name     string
		gate     func(t *testing.T) keytransparency.Gate
		wantCode string
	}{
		{name: "no trust file", gate: func(*testing.T) keytransparency.Gate { return keytransparency.Gate{} }},
		{name: "valid trust file", gate: func(t *testing.T) keytransparency.Gate {
			return keytransparency.Gate{Trust: testTrust(t)}
		}, wantCode: "key_transparency_unverified"},
		{name: "unusable trust file", gate: func(*testing.T) keytransparency.Gate { return invalidGate() },
			wantCode: "key_transparency_trust_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newWrapFixture(t)
			old, next := newTrustKey(t), newTrustKey(t)
			pinPeerTOFU(t, fixture, old)
			fixture.deps.KeyTransparency = tc.gate(t)

			resp := HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
				OwnerAccountID: pinOwnerA,
				AccountID:      pinPeer,
				PublicKey:      next.pair.PublicKey,
				RotationStatements: []proto.KeyRotationStatement{
					statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
				},
			})
			pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
			if tc.wantCode == "" {
				if data := evaluateData(t, resp); data.State != string(keychain.PeerKeyPinStateRotated) {
					t.Fatalf("state = %q, want rotated", data.State)
				}
				return
			}
			if resp.Success || resp.ErrorCode != tc.wantCode {
				t.Fatalf("response = %+v, want %s", resp, tc.wantCode)
			}
			if pin.Fingerprint != old.fingerprint {
				t.Fatalf("pin moved to %q on a refused change", pin.Fingerprint)
			}
		})
	}
}
