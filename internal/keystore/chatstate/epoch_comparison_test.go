package chatstate

import (
	"crypto/sha256"
	"errors"
	"testing"
)

type epochComparisonFake struct {
	fakeCipher
	mismatchEpoch bool
}

func (c *epochComparisonFake) EpochComparisonDigest(conversationID []byte) (uint64, []byte, error) {
	epoch := c.epoch
	if c.mismatchEpoch {
		epoch++
	}
	input := append(append([]byte(nil), conversationID...), byte(epoch))
	digest := sha256.Sum256(input)
	return epoch, digest[:], nil
}

func TestCompareEpochReturnsBoundDigestWithoutChangingState(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.SaveJoinedGroupState(testConvA, noWatermark, fakeState(4, 2, 7), 4, 2, nil); err != nil {
		t.Fatal(err)
	}
	before := readRecordForTest(t, store, testConvA)

	got, err := store.CompareEpoch(testConvA, noWatermark, &epochComparisonFake{})
	if err != nil || got.Epoch != 4 || len(got.Digest) != EpochComparisonDigestBytes {
		t.Fatalf("comparison = %+v, %v", got, err)
	}
	after := readRecordForTest(t, store, testConvA)
	if after.Generation != before.Generation || string(after.GroupState) != string(before.GroupState) {
		t.Fatal("epoch comparison changed the stored MLS record")
	}
}

func TestCompareEpochRefusesPendingOrMismatchedState(t *testing.T) {
	store, _ := newTestStore(t)
	seedGroupState(t, store, testConvA, 4, 2, 7)
	_, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
		ClientCommitID: testCommitA,
		Plan:           CommitPlan{UserInitiated: true},
	}, &fakeCommitter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareEpoch(testConvA, noWatermark, &epochComparisonFake{}); !errors.Is(err, ErrCommitPending) {
		t.Fatalf("comparison with pending Commit = %v, want ErrCommitPending", err)
	}

	store2, _ := newTestStore(t)
	if _, err := store2.SaveJoinedGroupState(testConvA, noWatermark, fakeState(4, 2, 7), 4, 2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.CompareEpoch(testConvA, noWatermark, &epochComparisonFake{mismatchEpoch: true}); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("comparison with a mismatched MLS epoch = %v, want ErrRekeyRequired", err)
	}
}
