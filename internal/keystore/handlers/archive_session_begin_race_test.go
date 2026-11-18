// archive_session_begin_race_test.go — a begin decides under the lock, then
// generates its key outside it, then decides again under the lock on a fresh
// read before it writes. No interleaving lets two begins both store a key or
// a begin overwrite a live one; a key that lost the race is never stored.

package handlers

import (
	"sync/atomic"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// countKeygen replaces the keygen seam with one that counts its calls and
// runs during before returning the first key it generates.
func countKeygen(t *testing.T, during func()) *atomic.Int32 {
	t.Helper()
	restore := archiveSessionKeygen
	t.Cleanup(func() { archiveSessionKeygen = restore })
	var calls atomic.Int32
	archiveSessionKeygen = func() (*crypto.KeyPair, error) {
		n := calls.Add(1)
		pair, err := restore()
		if n == 1 && during != nil {
			during()
		}
		return pair, err
	}
	return &calls
}

// A begin the slot refuses (a live session) or replays generates no key.
func TestArchiveSessionBegin_RefusedOrReplayedBeginGeneratesNoKey(t *testing.T) {
	deps, _, _ := newOrgSessionDeps(t)
	beginWithID(deps, testOrgA, testBeginID1)
	calls := countKeygen(t, nil)
	beginWithID(deps, testOrgA, testBeginID2)
	beginWithID(deps, testOrgA, testBeginID1)
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d keys generated for a refused or replayed begin", n)
	}
}

// Another begin lands while this one generates its key (pinned by the seam,
// not by timing): the second decision sees the session it stored, refuses
// (another begin_id) or replays it (the same begin_id), and this begin's key
// is not stored.
func TestArchiveSessionBegin_BeginDuringKeygenIsNeitherOverwrittenNorDuplicated(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inner      string
		wantReplay bool
	}{
		{"another begin_id", testBeginID2, false},
		{"the same begin_id", testBeginID1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, _, _ := newOrgSessionDeps(t)
			var inner proto.BaseResponse
			countKeygen(t, func() { inner = beginWithID(deps, testOrgA, tc.inner) })
			outer := beginWithID(deps, testOrgA, testBeginID1)
			if !inner.Success {
				t.Fatalf("the begin that ran during keygen: %q", inner.ErrorCode)
			}
			innerFP := inner.Data.(proto.ArchiveSessionBeginResponseData).Fingerprint
			if tc.wantReplay {
				data := outer.Data.(proto.ArchiveSessionBeginResponseData)
				if !outer.Success || !data.Replayed || data.Fingerprint != innerFP {
					t.Fatal("the same begin_id was not answered with the stored session")
				}
			} else {
				requireActiveRefusal(t, outer, innerFP)
			}
			if !archiveSessionFingerprintMatches(deps, testOrgA, innerFP) {
				t.Fatal("the key generated before the other begin stored was written over it")
			}
		})
	}
}

// Two begins of one organization released through one barrier: with
// different begin_ids exactly one stores a key and the other is refused;
// with the same begin_id both get that one session, one of them replayed.
func TestArchiveSessionBegin_ConcurrentBeginsStoreOneKey(t *testing.T) {
	for round := range sessionRaceRounds {
		for _, same := range []bool{false, true} {
			deps, store, _ := newOrgSessionDeps(t)
			second := testBeginID2
			if same {
				second = testBeginID1
			}
			var r1, r2 proto.BaseResponse
			raceActors(t,
				func() { r1 = beginWithID(deps, testOrgA, testBeginID1) },
				func() { r2 = beginWithID(deps, testOrgA, second) },
			)
			var stored []proto.ArchiveSessionBeginResponseData
			refused := 0
			for _, r := range []proto.BaseResponse{r1, r2} {
				switch {
				case r.Success:
					stored = append(stored, r.Data.(proto.ArchiveSessionBeginResponseData))
				case r.ErrorCode == string(errs.ErrCodeArchiveSessionActive):
					refused++
				default:
					t.Fatalf("round %d: unexpected answer %q", round, r.ErrorCode)
				}
			}
			if same {
				if len(stored) != 2 || stored[0].Fingerprint != stored[1].Fingerprint || stored[0].Replayed == stored[1].Replayed {
					t.Fatalf("round %d same begin_id: two sessions or no replay", round)
				}
			} else if len(stored) != 1 || refused != 1 {
				t.Fatalf("round %d: %d stored, %d refused", round, len(stored), refused)
			}
			if !archiveSessionFingerprintMatches(deps, testOrgA, stored[0].Fingerprint) {
				t.Fatalf("round %d: the slot does not hold the answered key", round)
			}
			if !probeHalvesMatch(t, orgSlotPEM(t, store, testOrgA), orgSlotPublic(store, testOrgA)) {
				t.Fatalf("round %d: slot halves of different begins", round)
			}
		}
	}
}

func probeHalvesMatch(t *testing.T, privPEM, pubPEM string) bool {
	t.Helper()
	priv, err := crypto.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return priv.PublicKey.N.Cmp(pub.N) == 0
}
