package clipboard

import "testing"

// TestSelectSink_Matrix pins the whole 2x2 decision. The load-bearing rows
// are (true, false) — the default e2e sink must stay MemoryClipboard so the
// existing suite and clipboard_get_last_hash keep working — and (false, true)
// — the opt-in must not be reachable outside e2e mode.
func TestSelectSink_Matrix(t *testing.T) {
	cases := []struct {
		name    string
		e2eMode bool
		optIn   bool
		want    Sink
	}{
		{"production ignores the opt-in", false, true, SinkOS},
		{"production without opt-in", false, false, SinkOS},
		{"e2e default stays in memory", true, false, SinkMemory},
		{"e2e opt-in takes the OS clipboard", true, true, SinkOS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelectSink(tc.e2eMode, tc.optIn); got != tc.want {
				t.Fatalf("SelectSink(%v, %v) = %v, want %v",
					tc.e2eMode, tc.optIn, got, tc.want)
			}
		})
	}
}

// TestSelectSink_OptInIsNoopOutsideE2E states the security property on its
// own: toggling the flag can never change the production sink.
func TestSelectSink_OptInIsNoopOutsideE2E(t *testing.T) {
	if SelectSink(false, false) != SelectSink(false, true) {
		t.Fatal("KEEPER_E2E_OS_CLIPBOARD must not change the sink outside e2e mode")
	}
}
