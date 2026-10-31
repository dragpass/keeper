package dispatch

import "testing"

func TestPersonalDEKBindIsAppOnlyWithoutPlaintext(t *testing.T) {
	entry, ok := actionRegistry["personal_dek_bind"]
	if !ok || !entry.appOnly || entry.mcp || entry.plaintext {
		t.Fatal("personal DEK binding must be App-only without plaintext output")
	}
}
