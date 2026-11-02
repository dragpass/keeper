package changetrack

import (
	"crypto/rand"
	"math"
	"testing"
)

// First observation only sets a baseline: no previous record, sequence 1.
func TestObserve_NoPreviousRecordIsBaseline(t *testing.T) {
	dek := testDEK(t)
	s := groupScope(testEntryA)
	got, rec, err := Observe(rand.Reader, s, Current{DEK: dek, DekVersion: 5}, nil, []byte("value-one"))
	if err != nil {
		t.Fatal("observe failed")
	}
	if got != VerdictBaseline || rec.Seq != 1 || rec.DekVersion != 5 {
		t.Fatalf("verdict %q seq %d version %d, want baseline 1 5", got, rec.Seq, rec.DekVersion)
	}
	if Compare(dek, s, rec, []byte("value-one")) != VerdictSame {
		t.Fatal("baseline record does not describe the observed value")
	}
}

// A DEK rotation between two saves of the same value is not a change.
func TestObserve_SameValueAcrossDEKRotationIsSame(t *testing.T) {
	oldDEK, newDEK := testDEK(t), testDEK(t)
	s := groupScope(testEntryA)
	prev, err := Seal(rand.Reader, oldDEK, s, 4, 9, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	got, rec, err := Observe(rand.Reader, s, Current{DEK: newDEK, DekVersion: 5},
		&Previous{Record: prev, DEK: oldDEK}, []byte("value-one"))
	if err != nil {
		t.Fatal("observe failed")
	}
	if got != VerdictSame || rec.Seq != 10 || rec.DekVersion != 5 {
		t.Fatalf("verdict %q seq %d version %d, want same 10 5", got, rec.Seq, rec.DekVersion)
	}
}

func TestObserve_NewValueIsChanged(t *testing.T) {
	dek := testDEK(t)
	s := groupScope(testEntryA)
	prev, err := Seal(rand.Reader, dek, s, 5, 1, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	got, rec, err := Observe(rand.Reader, s, Current{DEK: dek, DekVersion: 5},
		&Previous{Record: prev, DEK: dek}, []byte("value-two"))
	if err != nil || got != VerdictChanged {
		t.Fatalf("verdict %q, want changed", got)
	}
	if Compare(dek, s, rec, []byte("value-two")) != VerdictSame {
		t.Fatal("new record does not describe the new value")
	}
}

// A previous record whose DEK is unavailable (lost grant, replaced comparison
// key) is unknown, and a fresh baseline is still produced.
func TestObserve_UnavailablePreviousDEKIsUnknownWithNewBaseline(t *testing.T) {
	dek := testDEK(t)
	s := groupScope(testEntryA)
	prev, err := Seal(rand.Reader, testDEK(t), s, 2, 3, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	got, rec, err := Observe(rand.Reader, s, Current{DEK: dek, DekVersion: 5},
		&Previous{Record: prev}, []byte("value-two"))
	if err != nil {
		t.Fatal("observe failed")
	}
	if got != VerdictUnknown || rec.Seq != 4 {
		t.Fatalf("verdict %q seq %d, want unknown 4", got, rec.Seq)
	}
	if Compare(dek, s, rec, []byte("value-two")) != VerdictSame {
		t.Fatal("unknown verdict did not leave a usable baseline")
	}
}

func TestObserve_RefusesSequenceOverflow(t *testing.T) {
	dek := testDEK(t)
	s := groupScope(testEntryA)
	prev, err := Seal(rand.Reader, dek, s, 5, math.MaxUint64, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	if _, _, err := Observe(rand.Reader, s, Current{DEK: dek, DekVersion: 5},
		&Previous{Record: prev, DEK: dek}, []byte("value-one")); err == nil {
		t.Fatal("observe accepted a sequence that cannot advance")
	}
}
