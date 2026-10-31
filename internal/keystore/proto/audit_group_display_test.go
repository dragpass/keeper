package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditGroupDisplayDecisionUsesSeparateTableBoundCanonical(t *testing.T) {
	d := AuditGroupDisplayDecision{
		CurrentGroupDisplayDecision: validGroupDisplayDecision(),
		TableID:                     "55555555-5555-4555-8555-555555555555", TableDigest: strings.Repeat("d", 64),
	}
	want := "dragpass.group.audit-display|1|" + d.Challenge +
		"|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222" +
		"|33333333-3333-4333-8333-333333333333|1000000001|44444444-4444-4444-8444-444444444444" +
		"|7|" + strings.Repeat("a", 64) + "|55555555-5555-4555-8555-555555555555|" + strings.Repeat("d", 64) +
		"|" + strings.Repeat("b", 64) + "|" + strings.Repeat("c", 64) + "|1000|1010|3"
	if got := AuditGroupDisplayDecisionCanonical(d); got != want {
		t.Fatal("audit canonical differs from API's signed field order")
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("valid audit decision refused: %v", err)
	}
	d.TableDigest = strings.Repeat("0", 64)
	if err := d.Validate(); err == nil {
		t.Fatal("zero table digest accepted")
	}
	d.TableDigest = strings.Repeat("d", 64)
	wire, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"session_issued_at_nanos":"1000000001"`) {
		t.Fatal("audit decision lost exact session nanoseconds on JSON wire")
	}
}
