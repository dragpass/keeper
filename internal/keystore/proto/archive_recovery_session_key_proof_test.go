package proto

import (
	"strconv"
	"strings"
	"testing"
)

// ariadneSessionKeyProofCanonical is the server's statement encoder,
// sessionkeyproof.Canonical in ariadne, copied verbatim so the Keeper
// encoding is checked against an implementation it does not share.
func ariadneSessionKeyProofCanonical(domain string, fields ...string) string {
	var b strings.Builder
	b.WriteString(domain)
	for _, f := range fields {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

const (
	recoveryProofAccount = "00000000-0000-4000-8000-000000000001"
	recoveryProofDevice  = "00000000-0000-4000-8000-000000000007"
	recoveryProofOrg     = "00000000-0000-4000-8000-000000000002"
	recoveryProofGroup   = "00000000-0000-4000-8000-000000000006"
)

func recoveryProofRequest() ArchiveRecoverySessionKeyProof {
	return ArchiveRecoverySessionKeyProof{OrgID: recoveryProofOrg, GroupID: recoveryProofGroup, DekVersion: 12, SessionSPKI: strings.Repeat("ab", 32)}
}

// The fixed vector pins the exact bytes the server verifies: the recovery
// domain, then account, device, org, group, decimal DEK version and SPKI,
// each as len:value.
func TestArchiveRecoverySessionKeyProofWireVector(t *testing.T) {
	r := recoveryProofRequest()
	spki := strings.Repeat("ab", 32)
	want := "dragpass.archive.recovery.session-key|1" +
		"|36:" + recoveryProofAccount +
		"|36:" + recoveryProofDevice +
		"|36:" + recoveryProofOrg +
		"|36:" + recoveryProofGroup +
		"|2:12" +
		"|64:" + spki
	got := r.Canonical(recoveryProofAccount, recoveryProofDevice, spki)
	if got != want {
		t.Fatalf("statement\n got %q\nwant %q", got, want)
	}
	server := ariadneSessionKeyProofCanonical("dragpass.archive.recovery.session-key|1", recoveryProofAccount, recoveryProofDevice,
		recoveryProofOrg, recoveryProofGroup, strconv.Itoa(r.DekVersion), spki)
	if got != server {
		t.Fatalf("statement differs from the server encoding\n got %q\nwant %q", got, server)
	}
}

// The statement signs the SPKI Keeper derived, not the requested one.
func TestArchiveRecoverySessionKeyProofSignsLocalSPKI(t *testing.T) {
	r := recoveryProofRequest()
	local := strings.Repeat("cd", 32)
	if !strings.HasSuffix(r.Canonical(recoveryProofAccount, recoveryProofDevice, local), "|64:"+local) {
		t.Fatal("statement does not end with the local SPKI")
	}
}

func TestArchiveRecoverySessionKeyProofValidate(t *testing.T) {
	if err := recoveryProofRequest().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ArchiveRecoverySessionKeyProof){
		"org":            func(r *ArchiveRecoverySessionKeyProof) { r.OrgID = "" },
		"org uppercase":  func(r *ArchiveRecoverySessionKeyProof) { r.OrgID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
		"group":          func(r *ArchiveRecoverySessionKeyProof) { r.GroupID = "not-a-uuid" },
		"dek zero":       func(r *ArchiveRecoverySessionKeyProof) { r.DekVersion = 0 },
		"dek negative":   func(r *ArchiveRecoverySessionKeyProof) { r.DekVersion = -1 },
		"spki uppercase": func(r *ArchiveRecoverySessionKeyProof) { r.SessionSPKI = strings.Repeat("AB", 32) },
		"spki short":     func(r *ArchiveRecoverySessionKeyProof) { r.SessionSPKI = "ab" },
		"spki missing":   func(r *ArchiveRecoverySessionKeyProof) { r.SessionSPKI = "" },
	} {
		r := recoveryProofRequest()
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestArchiveRecoverySessionKeyProofWithReservedID(t *testing.T) {
	r := recoveryProofRequest()
	session := "5abd03bb-7fa2-4caf-bddc-6bf43542eb1c"
	r.SessionID = &session
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	local := strings.Repeat("cd", 32)
	want := ariadneSessionKeyProofCanonical("dragpass.archive.recovery.session-key|2",
		recoveryProofAccount, recoveryProofDevice, r.OrgID, session, r.GroupID, "12", local)
	if got := r.Canonical(recoveryProofAccount, recoveryProofDevice, local); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, invalid := range []string{"", "bad", strings.ToUpper(session)} {
		r.SessionID = &invalid
		if r.Validate() == nil {
			t.Fatalf("accepted invalid session ID %q", invalid)
		}
	}
}
