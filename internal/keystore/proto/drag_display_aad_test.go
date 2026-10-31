package proto

import "testing"

func TestDragDisplayAADRequiresCanonicalScopeAndExpiry(t *testing.T) {
	value := "dragpass.drag-display|1|group|3|11111111-1111-4111-8111-111111111111||0|"
	parsed, err := ParseDragDisplayAAD([]byte(value))
	if err != nil || parsed.Scope != "group" || parsed.DekVersion != 3 || parsed.ExpiresAt != 0 {
		t.Fatal("canonical display AAD was refused")
	}
	for _, invalid := range []string{
		"dragpass.drag-display|1|group|03|11111111-1111-4111-8111-111111111111||0|",
		"dragpass.drag-display|1|group|3|11111111-1111-4111-8111-111111111111||00|",
		"dragpass.drag-display|1|personal|1|11111111-1111-4111-8111-111111111111||0|",
		"dragpass.drag-display|1|group|3|||0|",
	} {
		if _, err := ParseDragDisplayAAD([]byte(invalid)); err == nil {
			t.Fatal("invalid display AAD was accepted")
		}
	}
}
