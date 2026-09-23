package proto

import (
	"strings"
	"testing"
)

const (
	mlsLeafGoldenAccountID   = "11111111-1111-4111-8111-111111111111"
	mlsLeafGoldenDeviceID    = "44444444-4444-4444-8444-444444444444"
	mlsLeafGoldenFingerprint = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	mlsLeafGoldenNotBefore   = 1788999000

	// ariadne pins the same literal. Both sides sign and verify these bytes.
	mlsLeafGoldenCanonical = "dragpass.mls.leaf|1|11111111-1111-4111-8111-111111111111|44444444-4444-4444-8444-444444444444|66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|1788999000|enroll"
)

func goldenMLSLeafDeclaration() MLSLeafDeclaration {
	return MLSLeafDeclaration{
		AccountID:               mlsLeafGoldenAccountID,
		DeviceID:                mlsLeafGoldenDeviceID,
		SignatureKey:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		SignatureKeyFingerprint: mlsLeafGoldenFingerprint,
		NotBefore:               mlsLeafGoldenNotBefore,
		Reason:                  MLSLeafReasonEnroll,
		Signature:               "c2ln",
	}
}

func TestMLSLeafCanonical_GoldenVector(t *testing.T) {
	got := goldenMLSLeafDeclaration().Canonical()
	if got != mlsLeafGoldenCanonical {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, mlsLeafGoldenCanonical)
	}
	if n := strings.Count(got, "|"); n != 6 {
		t.Fatalf("canonical has %d pipes, want 6", n)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatal("canonical contains a line break")
	}
}

func TestMLSLeafCanonical_EveryFieldMoves(t *testing.T) {
	base := goldenMLSLeafDeclaration()
	mutations := map[string]func(*MLSLeafDeclaration){
		"account_id":  func(d *MLSLeafDeclaration) { d.AccountID = "22222222-2222-4222-8222-222222222222" },
		"device_id":   func(d *MLSLeafDeclaration) { d.DeviceID = "55555555-5555-4555-8555-555555555555" },
		"fingerprint": func(d *MLSLeafDeclaration) { d.SignatureKeyFingerprint = strings.Repeat("a", 64) },
		"not_before":  func(d *MLSLeafDeclaration) { d.NotBefore++ },
		"reason":      func(d *MLSLeafDeclaration) { d.Reason = MLSLeafReasonRotate },
	}
	for name, mutate := range mutations {
		d := base
		mutate(&d)
		if d.Canonical() == mlsLeafGoldenCanonical {
			t.Errorf("changing %s left the canonical unchanged", name)
		}
	}
	// The domain and version are constants rather than fields; a change to
	// either must also move the bytes.
	if !strings.HasPrefix(mlsLeafGoldenCanonical, MLSLeafCanonicalDomain+"|1|") {
		t.Fatal("domain or version slot moved")
	}
}

func TestMLSLeafDeclaration_ValidateRejectsUnknownReason(t *testing.T) {
	for _, reason := range []string{"", "revoke", "compromise", "Enroll", "voluntary"} {
		d := goldenMLSLeafDeclaration()
		d.Reason = reason
		if err := d.Validate(); err == nil {
			t.Errorf("reason %q accepted", reason)
		}
	}
	if err := goldenMLSLeafDeclaration().Validate(); err != nil {
		t.Fatalf("golden declaration rejected: %v", err)
	}
}

func TestMLSLeafDeclareRequest_Validate(t *testing.T) {
	ok := MLSLeafDeclareRequest{
		ChallengeToken:  "challenge",
		ServerSignature: "sig",
		AccountID:       mlsLeafGoldenAccountID,
		DeviceID:        mlsLeafGoldenDeviceID,
		NotBefore:       mlsLeafGoldenNotBefore,
		Reason:          MLSLeafReasonEnroll,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	bad := map[string]func(*MLSLeafDeclareRequest){
		"challenge":  func(r *MLSLeafDeclareRequest) { r.ChallengeToken = "" },
		"signature":  func(r *MLSLeafDeclareRequest) { r.ServerSignature = "" },
		"account":    func(r *MLSLeafDeclareRequest) { r.AccountID = "not-a-uuid" },
		"device":     func(r *MLSLeafDeclareRequest) { r.DeviceID = "" },
		"device|":    func(r *MLSLeafDeclareRequest) { r.DeviceID = "44444444-4444-4444-8444-44444444444|" },
		"not_before": func(r *MLSLeafDeclareRequest) { r.NotBefore = 0 },
		"reason":     func(r *MLSLeafDeclareRequest) { r.Reason = "revoke" },
	}
	for name, mutate := range bad {
		r := ok
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: invalid request accepted", name)
		}
	}
}

func TestParseMLSLeafChallenge(t *testing.T) {
	const nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token := "dragpass.mls.leaf.challenge|1|" + mlsLeafGoldenAccountID + "|" + mlsLeafGoldenDeviceID + "|" + nonce + "|1788999300"
	got, err := ParseMLSLeafChallenge(token)
	if err != nil {
		t.Fatalf("well-formed challenge refused: %v", err)
	}
	want := MLSLeafChallenge{AccountID: mlsLeafGoldenAccountID, DeviceID: mlsLeafGoldenDeviceID, Nonce: nonce, ExpiresAt: 1788999300}
	if got != want {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	for _, bad := range []string{
		"",
		"rotate-challenge-001",
		strings.Replace(token, "|1|", "|01|", 1),
		strings.Replace(token, nonce, strings.ToUpper(nonce), 1),
		strings.Replace(token, "1788999300", "+1788999300", 1),
		strings.Replace(token, "1788999300", "-1", 1),
		token + "\n",
	} {
		if _, err := ParseMLSLeafChallenge(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
