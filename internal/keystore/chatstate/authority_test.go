package chatstate

import (
	"errors"
	"strconv"
	"testing"
)

const (
	authA = "a1111111-1111-4111-8111-111111111111"
	authB = "b2222222-2222-4222-8222-222222222222"
	authC = "c3333333-3333-4333-8333-333333333333"
)

// fixedEvidence authorizes the removed leaves at the listed indices and
// reports a count of statements that do not verify.
type fixedEvidence struct {
	authorized []int
	invalid    int
}

func (f fixedEvidence) Authorized(change CommitChange) ([]bool, int, error) {
	out := make([]bool, len(change.Removed))
	for _, i := range f.authorized {
		out[i] = true
	}
	return out, f.invalid, nil
}

func room(owner string, admins ...string) *Roles {
	r, err := RolesFromEntries(RolesKindRoom, append([]RoleEntry{{AccountID: owner, Role: RoleOwner}},
		func() []RoleEntry {
			var out []RoleEntry
			for _, a := range admins {
				out = append(out, RoleEntry{AccountID: a, Role: RoleAdmin})
			}
			return out
		}()...))
	if err != nil {
		panic(err)
	}
	return &r
}

const authD = "d4444444-4444-4444-8444-444444444444"

func TestJudgeReceived_TheRules(t *testing.T) {
	abc := []string{authA, authB, authC}
	for name, tc := range map[string]struct {
		change CommitChange
		auth   CommitAuthority
		ok     bool
	}{
		"an update": {CommitChange{CommitterAccountID: authB}, CommitAuthority{}, true},
		"R1: the committer's own account": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authB}}, CommitAuthority{}, true},
		"R2: a remove paired with an add of the account": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Added: []string{authC}}, CommitAuthority{}, true},
		"S: a remove a verified statement covers": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{Evidence: fixedEvidence{authorized: []int{0}}}, true},
		"a statement that does not verify authorizes nothing": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{Evidence: fixedEvidence{invalid: 1}}, false},
		"RR: the owner removes a member": {
			CommitChange{CommitterAccountID: authA, Removed: []string{authC}, Before: abc, RolesBefore: room(authA, authB)},
			CommitAuthority{}, true},
		"RR: an admin removes a member": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: room(authA, authB)},
			CommitAuthority{}, true},
		"an admin cannot remove the owner": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authA}, Before: abc, RolesBefore: room(authA, authB)},
			CommitAuthority{}, false},
		"a member cannot remove a member": {
			CommitChange{CommitterAccountID: authC, Removed: []string{authB}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{}, false},
		"R3b holds only for a group without roles (legacy_temporary)": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc},
			CommitAuthority{CommitMembers: []string{authA, authB}, CommitMembersKnown: true}, true},
		"R3b is not authority in a room with roles": {
			CommitChange{CommitterAccountID: authC, Removed: []string{authB}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{CommitMembers: []string{authA, authC}, CommitMembersKnown: true}, false},
		"a same-set remove": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}},
			CommitAuthority{CommitMembers: []string{authA, authB, authC}, CommitMembersKnown: true}, false},
		"a remove with no evidence at all": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}}, CommitAuthority{}, false},
		"a plain member adds in a room": {
			CommitChange{CommitterAccountID: authC, Added: []string{authD}, Before: abc, Epoch: 3, RolesBefore: room(authA)},
			CommitAuthority{}, false},
		"an admin adds in a room": {
			CommitChange{CommitterAccountID: authB, Added: []string{authD}, Before: abc, Epoch: 3, RolesBefore: room(authA, authB)},
			CommitAuthority{}, true},
		"a DM adds nobody after its create": {
			CommitChange{CommitterAccountID: authA, Added: []string{authC}, Before: []string{authA, authB}, Epoch: 1,
				RolesBefore: &Roles{Kind: RolesKindDM}},
			CommitAuthority{}, false},
		// 임시, 정책 미충족 (legacy_temporary): a group without roles takes a
		// received Add on its leaf alone.
		"a legacy group takes an add on its leaf": {
			CommitChange{CommitterAccountID: authA, Added: []string{authC}}, CommitAuthority{}, true},
		"a roles change by an admin": {
			CommitChange{CommitterAccountID: authB, Before: abc, RolesBefore: room(authA, authB),
				RolesChange: RolesSet, RolesAfter: room(authB, authA)},
			CommitAuthority{}, false},
		"a roles change by the owner": {
			CommitChange{CommitterAccountID: authA, Before: abc, RolesBefore: room(authA, authB),
				RolesChange: RolesSet, RolesAfter: room(authB, authA)},
			CommitAuthority{}, true},
		"a change to another extension": {
			CommitChange{CommitterAccountID: authA, RolesBefore: room(authA), RolesChange: RolesOtherExtension},
			CommitAuthority{}, false},
		"any other proposal type": {
			CommitChange{CommitterAccountID: authA, OtherProposals: 1}, CommitAuthority{}, false},
	} {
		err := JudgeReceived(tc.change, tc.auth)
		if tc.ok != (err == nil) {
			t.Fatalf("%s: JudgeReceived = %v", name, err)
		}
		var refused *UnauthorizedCommitError
		if err != nil && (!errors.As(err, &refused) || refused.CommitterAccountID != tc.change.CommitterAccountID) {
			t.Fatalf("%s: refusal %v does not name the committer", name, err)
		}
	}
}

// fakePlanJudge describes a plan as a fixed change.
type fakePlanJudge struct {
	CommitCipher
	change   CommitChange
	evidence RemovalEvidence
}

func (f fakePlanJudge) PlanChange(CommitPlan) (CommitChange, error) { return f.change, nil }
func (f fakePlanJudge) Evidence() RemovalEvidence                   { return f.evidence }

func TestJudgeLocalPlan_BuildRules(t *testing.T) {
	abc := []string{authA, authB, authC}
	legacy := CommitChange{CommitterAccountID: authB, Before: abc}
	inRoom := func(c CommitChange) CommitChange { c.RolesBefore = room(authA, authB); c.Before = abc; return c }
	for name, tc := range map[string]struct {
		plan     CommitPlan
		change   CommitChange
		evidence RemovalEvidence
		want     error
	}{
		"an update": {CommitPlan{}, legacy, nil, nil},
		"an automated add": {CommitPlan{}, CommitChange{CommitterAccountID: authB, Added: []string{authD}}, nil,
			ErrCommitUnauthorized},
		"an add a person asked for, legacy": {CommitPlan{UserInitiated: true},
			CommitChange{CommitterAccountID: authB, Added: []string{authD}}, nil, nil},
		"an add a person asked for by a plain member of a room": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authC, Added: []string{authD}, Epoch: 2}), nil, ErrCommitUnauthorized},
		"the permit's word is no longer authority": {CommitPlan{},
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc}, nil, ErrCommitUnauthorized},
		"a remove a signed statement covers, by automation": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authC, Removed: []string{authB}}), fixedEvidence{authorized: []int{0}}, nil},
		"a statement that does not verify refuses the build": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authA, Removed: []string{authC}}), fixedEvidence{invalid: 1},
			ErrStatementUnverified},
		"an admin's remove, asked for": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authB, Removed: []string{authC}}), nil, nil},
		"an admin's remove, not asked for": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authB, Removed: []string{authC}}), nil, ErrCommitUnauthorized},
		"legacy: a member's remove a person asked for (R4i)": {CommitPlan{UserInitiated: true},
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc}, nil, nil},
		"an owner's roles change needs a person": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authA, RolesChange: RolesSet, RolesAfter: room(authB)}), nil,
			ErrCommitUnauthorized},
		"a migration by the creator as owner needs nobody": {CommitPlan{},
			CommitChange{CommitterAccountID: authA, CreatorAccountID: authA, Before: abc, RolesChange: RolesSet,
				RolesAfter: room(authA)}, nil, nil},
		"a migration by a member naming itself owner": {CommitPlan{UserInitiated: true},
			CommitChange{CommitterAccountID: authB, CreatorAccountID: authA, Before: abc, RolesChange: RolesSet,
				RolesAfter: room(authB)}, nil, ErrCommitUnauthorized},
		"a rejoin (R2)": {CommitPlan{},
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Added: []string{authC}}, nil, nil},
	} {
		err := judgeLocalPlan(tc.plan, fakePlanJudge{change: tc.change, evidence: tc.evidence})
		if (tc.want == nil) != (err == nil) || (err != nil && !errors.Is(err, tc.want)) {
			t.Fatalf("%s: judgeLocalPlan = %v, want %v", name, err, tc.want)
		}
	}
}

func TestTheForkRingIsBoundedAndComparesBytes(t *testing.T) {
	rec := newRecord(testOwner, testConvA)
	for e := uint64(1); e <= ConfirmedCommitCapacity+5; e++ {
		rec.noteConfirmed(e, []byte("commit "+strconv.FormatUint(e, 10)))
	}
	if len(rec.ConfirmedCommits) != ConfirmedCommitCapacity {
		t.Fatalf("ring holds %d", len(rec.ConfirmedCommits))
	}
	last := uint64(ConfirmedCommitCapacity + 5)
	if rec.forkAt(last, []byte("commit "+strconv.FormatUint(last, 10))) {
		t.Fatal("the same bytes read as a fork")
	}
	if !rec.forkAt(last, []byte("another commit")) {
		t.Fatal("other bytes for a held epoch did not read as a fork")
	}
	// An epoch the ring no longer holds cannot be compared (stated limit).
	if rec.forkAt(1, []byte("another commit")) {
		t.Fatal("an epoch older than the ring was judged")
	}
	// Noting an epoch again replaces it.
	rec.noteConfirmed(last, []byte("replacement"))
	if rec.forkAt(last, []byte("replacement")) || len(rec.ConfirmedCommits) != ConfirmedCommitCapacity {
		t.Fatal("a re-noted epoch was not replaced in place")
	}
}
