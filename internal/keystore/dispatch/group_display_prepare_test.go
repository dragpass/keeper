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

func TestGroupDisplayExecuteIsRegisteredWithoutMCPOrPlaintext(t *testing.T) {
	entry, ok := actionRegistry["group_display_execute"]
	if !ok {
		t.Fatal("group display execute is not registered")
	}
	if entry.appOnly || entry.mcp || entry.plaintext {
		t.Fatal("group display execute crossed its registered surface or plaintext boundary")
	}
}

func TestAuditGroupDisplayIsRegisteredWithoutMCPOrPlaintext(t *testing.T) {
	for _, name := range []string{"audit_group_display_prepare", "audit_group_display_execute"} {
		entry, ok := actionRegistry[name]
		if !ok || entry.appOnly || entry.mcp || entry.plaintext {
			t.Fatalf("audit group display crossed its registered surface or plaintext boundary: %s", name)
		}
	}
}
