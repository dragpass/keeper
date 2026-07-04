package proc

import "testing"

// TestDisableCoreDumps_NoError verifies that the call completes without error
// in a normal environment. On macOS / Linux, setting RLIMIT_CORE to 0 is
// possible without privileges (lowering one's own process limit is allowed
// without permission). On Windows / other OSes it is a noop and always nil.
func TestDisableCoreDumps_NoError(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatalf("DisableCoreDumps: %v", err)
	}
}
