package dispatch

import "testing"

func TestPersonalDisplayActionsAreNativeOnlyAndSealed(t *testing.T) {
	for _, name := range []string{"personal_display_prepare", "personal_display_execute"} {
		entry, ok := actionRegistry[name]
		if !ok || entry.appOnly || entry.mcp || entry.plaintext {
			t.Fatalf("personal display crossed its native, sealed boundary: %s", name)
		}
	}
}
