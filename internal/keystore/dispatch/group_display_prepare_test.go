package dispatch

import "testing"

func TestGroupDisplayPrepareIsRegisteredWithoutMCPOrPlaintext(t *testing.T) {
	entry, ok := actionRegistry["group_display_prepare"]
	if !ok {
		t.Fatal("group display prepare is not registered")
	}
	if entry.appOnly || entry.mcp || entry.plaintext {
		t.Fatal("group display prepare crossed its registered surface or plaintext boundary")
	}
}
