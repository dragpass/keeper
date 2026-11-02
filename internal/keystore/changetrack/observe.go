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

// Observe classifies value against prev and seals the record that replaces
// it. The new record always describes value, so an unknown verdict still
// leaves a usable baseline for the next save. The caller stores the new
// record only if the server's current sequence is still prev's.
func Observe(random io.Reader, s Scope, cur Current, prev *Previous, value []byte) (Verdict, Sealed, error) {
	verdict, seq := VerdictBaseline, uint64(1)
	if prev != nil {
		if prev.Record.Seq == math.MaxUint64 {
			return "", Sealed{}, ErrSequenceExhausted
		}
		verdict = VerdictUnknown
		if prev.DEK != nil {
			verdict = Compare(prev.DEK, s, prev.Record, value)
		}
		seq = prev.Record.Seq + 1
	}
	rec, err := Seal(random, cur.DEK, s, cur.DekVersion, seq, value)
	if err != nil {
		return "", Sealed{}, err
	}
	return verdict, rec, nil
}
