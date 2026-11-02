package changetrack

import (
	"errors"
	"io"
	"math"
)

// Current is the DEK the new token is sealed under. The new record uses it too.
type Current struct {
	DEK        []byte
	DekVersion int
}

// Previous is the record the server holds for the entry. DEK is the key of
// Record.DekVersion, or nil when this Keeper cannot open that version; the
// verdict is then unknown.
type Previous struct {
	Record Sealed
	DEK    []byte
}

// ErrSequenceExhausted — the previous record's sequence cannot advance.
var ErrSequenceExhausted = errors.New("change record sequence exhausted")

// Next classifies value against prev and returns the sequence of the record
// that replaces it. prevDEK is the key of prev.DekVersion, or nil when this
// Keeper cannot open that version (the verdict is then unknown). A caller
// that holds the previous and the current DEK under separate locks calls Next
// under the first and Seal under the second; Observe does both with one key.
func Next(s Scope, prev *Sealed, prevDEK []byte, value []byte) (Verdict, uint64, error) {
	if prev == nil {
		return VerdictBaseline, 1, nil
	}
	if prev.Seq == math.MaxUint64 {
		return "", 0, ErrSequenceExhausted
	}
	verdict := VerdictUnknown
	if prevDEK != nil {
		verdict = Compare(prevDEK, s, *prev, value)
	}
	return verdict, prev.Seq + 1, nil
}

// Observe classifies value against prev and seals the record that replaces
// it. The new record always describes value, so an unknown verdict still
// leaves a usable baseline for the next save. The caller stores the new
// record only if the server's current sequence is still prev's.
func Observe(random io.Reader, s Scope, cur Current, prev *Previous, value []byte) (Verdict, Sealed, error) {
	var prevRecord *Sealed
	var prevDEK []byte
	if prev != nil {
		prevRecord, prevDEK = &prev.Record, prev.DEK
	}
	verdict, seq, err := Next(s, prevRecord, prevDEK, value)
	if err != nil {
		return "", Sealed{}, err
	}
	rec, err := Seal(random, cur.DEK, s, cur.DekVersion, seq, value)
	if err != nil {
		return "", Sealed{}, err
	}
	return verdict, rec, nil
}
