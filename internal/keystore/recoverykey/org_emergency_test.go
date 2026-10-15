// org_emergency_test.go — the organization emergency recovery code seed
// against the cross-repository golden vector. testdata/org-emergency-code-v1.json
// is the same file ariadne and dragpass check in; dragpass recomputes the seed
// with WebCrypto, so two HKDF implementations agree byte for byte.

package recoverykey

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type orgEmergencyVectors struct {
	SeedDerivation struct {
		SaltPrefix string `json:"salt_prefix"`
		Info       string `json:"info"`
		Vectors    []struct {
			OrgID      string `json:"org_id"`
			Code       string `json:"code"`
			Normalized string `json:"normalized"`
			SeedB64    string `json:"seed_b64"`
		} `json:"vectors"`
		DomainSeparation struct {
			OrgID               string `json:"org_id"`
			Code                string `json:"code"`
			RecoveryInfoSeedB64 string `json:"recovery_info_seed_b64"`
		} `json:"domain_separation"`
		Invalid []struct {
			OrgID  string `json:"org_id"`
			Code   string `json:"code"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	} `json:"seed_derivation"`
}

func loadOrgEmergencyVectors(t *testing.T) orgEmergencyVectors {
	t.Helper()
	raw, err := os.ReadFile("../testdata/org-emergency-code-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v orgEmergencyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDeriveOrgEmergencySeedMatchesTheGoldenVector(t *testing.T) {
	v := loadOrgEmergencyVectors(t).SeedDerivation
	if v.Info != OrgEmergencyAuthInfo || v.SaltPrefix != "org:" {
		t.Fatalf("fixture domain %q / %q", v.Info, v.SaltPrefix)
	}
	if len(v.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vec := range v.Vectors {
		normalized, err := Normalize([]byte(vec.Code))
		if err != nil || string(normalized) != vec.Normalized {
			t.Fatalf("Normalize(%q) = %q, %v", vec.Code, normalized, err)
		}
		seed, err := DeriveOrgEmergencySeed([]byte(vec.Code), vec.OrgID)
		if err != nil {
			t.Fatalf("derive %q: %v", vec.Code, err)
		}
		if got := base64.StdEncoding.EncodeToString(seed); got != vec.SeedB64 {
			t.Fatalf("seed for %q = %s, want %s", vec.Code, got, vec.SeedB64)
		}
	}
}

// The org seed of a code is not the account recovery seed of the same 24
// characters under the same salt: the info string separates them.
func TestDeriveOrgEmergencySeedIsSeparatedFromAccountRecovery(t *testing.T) {
	d := loadOrgEmergencyVectors(t).SeedDerivation.DomainSeparation
	recoverySeed, _, err := Derive([]byte(d.Code), "org:"+d.OrgID, Version)
	if err != nil {
		t.Fatal(err)
	}
	if recoverySeed != d.RecoveryInfoSeedB64 {
		t.Fatalf("recovery-info seed = %s, fixture %s", recoverySeed, d.RecoveryInfoSeedB64)
	}
	seed, err := DeriveOrgEmergencySeed([]byte(d.Code), d.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(seed) == recoverySeed {
		t.Fatal("org emergency seed equals the account recovery seed")
	}
}

func TestDeriveOrgEmergencySeedRejectsBadCodesAndEmptyOrg(t *testing.T) {
	for _, vec := range loadOrgEmergencyVectors(t).SeedDerivation.Invalid {
		// The org id form is the request validator's job; this package only
		// refuses codes outside the RK24 format.
		if _, err := Normalize([]byte(vec.Code)); err != nil {
			if _, derr := DeriveOrgEmergencySeed([]byte(vec.Code), "5b0e8b8e-3f4a-4c55-9d2e-0a1b2c3d4e5f"); derr == nil {
				t.Fatalf("%s: derived a seed", vec.Reason)
			}
		}
	}
	if _, err := DeriveOrgEmergencySeed([]byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"), ""); err == nil {
		t.Fatal("empty org id derived a seed")
	}
}
