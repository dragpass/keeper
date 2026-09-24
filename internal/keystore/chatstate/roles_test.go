package chatstate

import (
	"errors"
	"testing"
)

// The golden vectors mls/src/roles.rs pins too: both sides must read one
// payload one way.
const (
	rolesA = "0a000000-0000-4000-8000-000000000001"
	rolesB = "0b000000-0000-4000-8000-000000000002"
	rolesC = "0c000000-0000-4000-8000-000000000003"
)

func TestRoles_PayloadRoundTripsAndIsStrict(t *testing.T) {
	r := Roles{Kind: RolesKindRoom, Owner: rolesB, Admins: []string{rolesA, rolesC}}
	want := "dragpass.chat.roles|1|room|" + rolesA + ":admin," + rolesB + ":owner," + rolesC + ":admin"
	if got := string(r.Encode()); got != want {
		t.Fatalf("encode = %s", got)
	}
	parsed, err := ParseRoles([]byte(want))
	if err != nil || !parsed.equal(r) {
		t.Fatalf("parse = %+v, %v", parsed, err)
	}
	if dm, err := ParseRoles([]byte("dragpass.chat.roles|1|dm|")); err != nil || dm.Kind != RolesKindDM {
		t.Fatalf("dm = %+v, %v", dm, err)
	}
	for _, bad := range []string{
		"dragpass.chat.roles|1|room|" + rolesB + ":owner," + rolesA + ":admin",
		"dragpass.chat.roles|1|room|" + rolesA + ":owner," + rolesB + ":owner",
		"dragpass.chat.roles|1|room|" + rolesA + ":admin",
		"dragpass.chat.roles|1|room|" + rolesA + ":member," + rolesB + ":owner",
		"dragpass.chat.roles|2|room|" + rolesA + ":owner",
		"dragpass.chat.roles|1|dm|" + rolesA + ":owner",
		"dragpass.chat.roles|1|room|" + rolesA + ":owner|",
	} {
		if _, err := ParseRoles([]byte(bad)); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
}

func TestRoles_OwnerlessClaim(t *testing.T) {
	before := room(rolesA, rolesB)
	claim := func(by string, after *Roles, tree ...string) string {
		return judgeRoles(CommitChange{CommitterAccountID: by, Before: tree, RolesBefore: before,
			RolesChange: RolesSet, RolesAfter: after})
	}
	if got := claim(rolesC, room(rolesC, rolesB), rolesB, rolesC); got == "" {
		t.Fatal("a member claimed while an admin holds a leaf")
	}
	if got := claim(rolesB, room(rolesB), rolesB, rolesC); got != "" {
		t.Fatalf("the admin's claim: %s", got)
	}
	if got := claim(rolesB, room(rolesB, rolesC), rolesB, rolesC); got == "" {
		t.Fatal("a claim that also grants a role")
	}
	if got := claim(rolesB, room(rolesB), rolesA, rolesB, rolesC); got == "" {
		t.Fatal("a claim while the owner still holds a leaf")
	}
	noAdmin := room(rolesA)
	if got := judgeRoles(CommitChange{CommitterAccountID: rolesC, Before: []string{rolesB, rolesC},
		RolesBefore: noAdmin, RolesChange: RolesSet, RolesAfter: room(rolesC)}); got != "" {
		t.Fatalf("with no admin, a member's claim: %s", got)
	}
}

// One active device per account, in every kind of group: a second leaf of an
// account in the tree comes in only in place of the one it holds (R2), on
// receipt as on build, whoever commits it.
func TestRoles_AnAccountThatHoldsALeafIsAddedAgainOnlyInItsPlace(t *testing.T) {
	for name, roles := range map[string]*Roles{"legacy": nil, "room": room(rolesA), "dm": {Kind: RolesKindDM}} {
		add := CommitChange{CommitterAccountID: rolesA, Before: []string{rolesA, rolesB}, RolesBefore: roles,
			Added: []string{rolesB}}
		if err := JudgeReceived(add, CommitAuthority{}); !errors.Is(err, ErrCommitUnauthorized) {
			t.Errorf("%s: a second leaf of an account in the tree = %v; want refused", name, err)
		}
		own := add
		own.Added = []string{rolesA}
		if err := JudgeReceived(own, CommitAuthority{}); !errors.Is(err, ErrCommitUnauthorized) {
			t.Errorf("%s: a second leaf of the committer's own account = %v; want refused", name, err)
		}
		replace := add
		replace.Removed = []string{rolesB}
		if err := JudgeReceived(replace, CommitAuthority{}); err != nil {
			t.Errorf("%s: a leaf in place of the account's own = %v", name, err)
		}
	}
}
