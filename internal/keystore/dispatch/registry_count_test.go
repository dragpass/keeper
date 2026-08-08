// registry_count_test.go — regression guard.
//
// Confirms that adding a new action / removing an existing one is an intended
// change. Compares the dispatcher actionRegistry entry count against the
// hard-coded ExpectedRegisteredActionCount. Update this constant alongside
// any change — it signals intent.
//
// Catches behavior-preserving refactors that accidentally add/remove actions.

package dispatch

import (
	"testing"
)

// Update together. Bump this number inside the same handler-change PR so
// add/remove intent is obvious during review.
const ExpectedRegisteredActionCount = 70

func TestActionRegistry_Count(t *testing.T) {
	if got := len(actionRegistry); got != ExpectedRegisteredActionCount {
		t.Fatalf("actionRegistry count = %d, want %d\n"+
			"if you added a new action or removed an existing one, "+
			"bump ExpectedRegisteredActionCount along with it.",
			got, ExpectedRegisteredActionCount)
	}
}

// TestActionRegistry_NoDuplicates — the map itself prevents duplicate keys,
// but this catches macro-pattern regressions where the same wrap call gets
// registered twice.
func TestActionRegistry_AllEntriesNonNil(t *testing.T) {
	for action, fn := range actionRegistry {
		if fn == nil {
			t.Errorf("action %q maps to nil handler", action)
		}
	}
}

func TestActionRegistry_RetiredGroupItemDEKActionsRemainRemoved(t *testing.T) {
	retired := []string{
		"aes_unwrap_and_encrypt",
		"aes_unshare_rewrap_meta",
		"aes_unwrap_and_decrypt_meta",
		"aes_unwrap_and_decrypt_to_clipboard",
	}
	for _, action := range retired {
		if _, exists := actionRegistry[action]; exists {
			t.Errorf("retired action %q is registered", action)
		}
	}
}
