package proto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type boundTokenVectors struct {
	AccountID          string `json:"account_id"`
	OrgID              string `json:"org_id"`
	GroupID            string `json:"group_id"`
	TableID            string `json:"table_id"`
	DekVersion         int    `json:"dek_version"`
	ExpiresAt          int64  `json:"expires_at"`
	PersonalNever      string `json:"personal_never"`
	PersonalExpiring   string `json:"personal_expiring"`
	GroupNever         string `json:"group_never"`
	GroupExpiring      string `json:"group_expiring"`
	GroupAuditExpiring string `json:"group_audit_expiring"`
}

func loadBoundTokenVectors(t *testing.T) boundTokenVectors {
	t.Helper()
	raw, err := os.ReadFile("../testdata/bound-token-aad-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v boundTokenVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBoundTokenAADCanonical_GoldenVector(t *testing.T) {
	v := loadBoundTokenVectors(t)
	never := TokenExpiry{}
	at := TokenExpiry{ExpiresAt: v.ExpiresAt}
	cases := map[string][2]string{
		"personal never":    {BoundPersonalTokenAAD(v.AccountID, never), v.PersonalNever},
		"personal expiring": {BoundPersonalTokenAAD(v.AccountID, at), v.PersonalExpiring},
		"group never":       {BoundGroupTokenAAD(v.OrgID, v.GroupID, v.DekVersion, "", never), v.GroupNever},
		"group expiring":    {BoundGroupTokenAAD(v.OrgID, v.GroupID, v.DekVersion, "", at), v.GroupExpiring},
		"group audit":       {BoundGroupTokenAAD(v.OrgID, v.GroupID, v.DekVersion, v.TableID, at), v.GroupAuditExpiring},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s: got %q want %q", name, c[0], c[1])
		}
	}
}

func TestParseTokenExpiry(t *testing.T) {
	if e, err := ParseTokenExpiry("never"); err != nil || !e.Never() {
		t.Fatalf("never: %+v %v", e, err)
	}
	if e, err := ParseTokenExpiry("1893456000"); err != nil || e.Never() || e.ExpiresAt != 1893456000 {
		t.Fatalf("epoch: %+v %v", e, err)
	}
	// A missing expiry is never read as "no expiry"; neither is 0, a leading
	// zero, a sign, whitespace or more than 11 digits.
	for _, bad := range []string{"", "0", "01893456000", "+1", "-1", " 1", "1 ", "123456789012", "Never", "1.5"} {
		if _, err := ParseTokenExpiry(bad); err == nil {
			t.Errorf("ParseTokenExpiry(%q) accepted", bad)
		}
	}
}

func TestTokenExpiryExpiredAt(t *testing.T) {
	e := TokenExpiry{ExpiresAt: 100}
	if e.ExpiredAt(99) || !e.ExpiredAt(100) || !e.ExpiredAt(101) {
		t.Fatal("epoch expiry must hold strictly before ExpiresAt")
	}
	if (TokenExpiry{}).ExpiredAt(1 << 40) {
		t.Fatal("never must not expire")
	}
}

func TestBoundTokenDomainIsReserved(t *testing.T) {
	if err := rejectReservedAAD(base64.StdEncoding.EncodeToString([]byte(BoundPersonalTokenAAD("6f1c2a8e-3b4d-4c5e-9f60-718293a4b5c6", TokenExpiry{}))), "aad_b64"); err == nil {
		t.Fatal("a caller could seal under the bound token domain")
	}
}
