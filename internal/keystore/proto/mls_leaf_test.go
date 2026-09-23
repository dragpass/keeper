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
	mlsLeafGoldenNotAfter    = 1791591000

	// ariadne pins the same literals. Both sides sign and verify these bytes.
	mlsLeafGoldenCanonical = "dragpass.mls.leaf|2|11111111-1111-4111-8111-111111111111|44444444-4444-4444-8444-444444444444|66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|1788999000|1791591000|enroll"
	mlsLeafGoldenAccepted  = "dragpass.mls.leaf.accepted|1|11111111-1111-4111-8111-111111111111|44444444-4444-4444-8444-444444444444|66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|1788999000|1791591000"
)

func goldenMLSLeafDeclaration() MLSLeafDeclaration {
	return MLSLeafDeclaration{
		AccountID:               mlsLeafGoldenAccountID,
		DeviceID:                mlsLeafGoldenDeviceID,
		SignatureKey:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		SignatureKeyFingerprint: mlsLeafGoldenFingerprint,
		NotBefore:               mlsLeafGoldenNotBefore,
		NotAfter:                mlsLeafGoldenNotAfter,
		Reason:                  MLSLeafReasonEnroll,
		Signature:               "c2ln",
	}
}

func TestMLSLeafCanonical_GoldenVector(t *testing.T) {
	got := goldenMLSLeafDeclaration().Canonical()
	if got != mlsLeafGoldenCanonical {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, mlsLeafGoldenCanonical)
	}
	if n := strings.Count(got, "|"); n != 7 {
		t.Fatalf("canonical has %d pipes, want 7", n)
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
		"not_after":   func(d *MLSLeafDeclaration) { d.NotAfter-- },
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
	if !strings.HasPrefix(mlsLeafGoldenCanonical, MLSLeafCanonicalDomain+"|2|") {
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
		NotAfter:        mlsLeafGoldenNotAfter,
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
		"not_after":  func(r *MLSLeafDeclareRequest) { r.NotAfter = 0 },
		"inverted":   func(r *MLSLeafDeclareRequest) { r.NotAfter = r.NotBefore },
		"too long":   func(r *MLSLeafDeclareRequest) { r.NotAfter = r.NotBefore + MLSLeafMaxValiditySeconds + 1 },
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

// The window rule is not_before < not_after <= not_before + 30 days, on the
// declaration as well as the request.
func TestMLSLeafDeclaration_ValidityWindow(t *testing.T) {
	cases := map[string]struct {
		notAfter int64
		ok       bool
	}{
		"one second":        {mlsLeafGoldenNotBefore + 1, true},
		"exactly 30 days":   {mlsLeafGoldenNotBefore + MLSLeafMaxValiditySeconds, true},
		"30 days and one":   {mlsLeafGoldenNotBefore + MLSLeafMaxValiditySeconds + 1, false},
		"equal":             {mlsLeafGoldenNotBefore, false},
		"before not_before": {mlsLeafGoldenNotBefore - 1, false},
		"absent":            {0, false},
	}
	for name, c := range cases {
		d := goldenMLSLeafDeclaration()
		d.NotAfter = c.notAfter
		if err := d.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestMLSLeafAccepted_GoldenVectorAndStrictParse(t *testing.T) {
	d := goldenMLSLeafDeclaration()
	token := MLSLeafAcceptedToken(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter)
	if token != mlsLeafGoldenAccepted {
		t.Fatalf("acceptance =\n%q\nwant\n%q", token, mlsLeafGoldenAccepted)
	}
	if n := strings.Count(token, "|"); n != 6 {
		t.Fatalf("acceptance has %d pipes, want 6", n)
	}
	got, err := ParseMLSLeafAccepted(mlsLeafGoldenAccepted)
	if err != nil {
		t.Fatalf("golden acceptance refused: %v", err)
	}
	if !got.Names(d) {
		t.Fatal("golden acceptance does not name the golden declaration")
	}
	for name, mutate := range map[string]func(*MLSLeafDeclaration){
		"account":     func(x *MLSLeafDeclaration) { x.AccountID = "22222222-2222-4222-8222-222222222222" },
		"device":      func(x *MLSLeafDeclaration) { x.DeviceID = "55555555-5555-4555-8555-555555555555" },
		"fingerprint": func(x *MLSLeafDeclaration) { x.SignatureKeyFingerprint = strings.Repeat("a", 64) },
		"not_before":  func(x *MLSLeafDeclaration) { x.NotBefore++ },
		"not_after":   func(x *MLSLeafDeclaration) { x.NotAfter++ },
	} {
		x := d
		mutate(&x)
		if got.Names(x) {
			t.Errorf("acceptance names a declaration with a different %s", name)
		}
	}

	for _, bad := range []string{
		"",
		mlsLeafGoldenCanonical,
		strings.Replace(mlsLeafGoldenAccepted, "accepted|1|", "accepted|2|", 1),
		strings.Replace(mlsLeafGoldenAccepted, "|1791591000", "|01791591000", 1),
		strings.Replace(mlsLeafGoldenAccepted, "|1791591000", "|1788999000", 1),
		strings.Replace(mlsLeafGoldenAccepted, "|1791591000", "|1791591001", 1),
		strings.Replace(mlsLeafGoldenAccepted, mlsLeafGoldenFingerprint, strings.ToUpper(mlsLeafGoldenFingerprint), 1),
		mlsLeafGoldenAccepted + "|enroll",
		mlsLeafGoldenAccepted + "\n",
	} {
		if _, err := ParseMLSLeafAccepted(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
