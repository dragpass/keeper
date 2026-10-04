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
	inRoom := room(authA, authB)
	for name, tc := range map[string]struct {
		change CommitChange
		auth   CommitAuthority
		ok     bool
	}{
		"an update": {CommitChange{CommitterAccountID: authB, Before: abc, RolesBefore: inRoom}, CommitAuthority{}, true},
		"R1: the committer's own account": {
			CommitChange{CommitterAccountID: authC, Removed: []string{authC}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{}, true},
		"R2: a remove paired with an add of the account": {
			CommitChange{CommitterAccountID: authC, Removed: []string{authB}, Added: []string{authB},
				Before: abc, RolesBefore: room(authA)}, CommitAuthority{}, true},
		"R2 in a room whose roles do not depend on leaf 0": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Added: []string{authC},
				Before: []string{authB, authC}, RolesBefore: room(authB)}, CommitAuthority{}, true},
		"S: a remove a verified statement covers": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{Evidence: fixedEvidence{authorized: []int{0}}}, true},
		"a statement that does not verify authorizes nothing": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{Evidence: fixedEvidence{invalid: 1}}, false},
		"RR: the owner removes a member": {
			CommitChange{CommitterAccountID: authA, Removed: []string{authC}, Before: abc, RolesBefore: inRoom},
			CommitAuthority{}, true},
		"RR: an admin removes a member": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc, RolesBefore: inRoom},
			CommitAuthority{}, true},
		"an admin cannot remove the owner": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authA}, Before: abc, RolesBefore: inRoom},
			CommitAuthority{}, false},
		"a member cannot remove a member": {
			CommitChange{CommitterAccountID: authC, Removed: []string{authB}, Before: abc, RolesBefore: room(authA)},
			CommitAuthority{}, false},
		"a plain member adds in a room": {
			CommitChange{CommitterAccountID: authC, Added: []string{authD}, Before: abc, Epoch: 3, RolesBefore: room(authA)},
			CommitAuthority{}, false},
		"an admin adds in a room": {
			CommitChange{CommitterAccountID: authB, Added: []string{authD}, Before: abc, Epoch: 3, RolesBefore: inRoom},
			CommitAuthority{}, true},
		"a DM adds nobody after its create": {
			CommitChange{CommitterAccountID: authA, Added: []string{authC}, Before: []string{authA, authB}, Epoch: 1,
				RolesBefore: &Roles{Kind: RolesKindDM}},
			CommitAuthority{}, false},
		"a roles change by an admin": {
			CommitChange{CommitterAccountID: authB, Before: abc, RolesBefore: inRoom,
				RolesChange: RolesSet, RolesAfter: room(authB, authA)},
			CommitAuthority{}, false},
		"a roles change by the owner": {
			CommitChange{CommitterAccountID: authA, Before: abc, RolesBefore: inRoom,
				RolesChange: RolesSet, RolesAfter: room(authB, authA)},
			CommitAuthority{}, true},
		"a change to another extension": {
			CommitChange{CommitterAccountID: authA, RolesBefore: room(authA), RolesChange: RolesOtherExtension},
			CommitAuthority{}, false},
		"any other proposal type": {
			CommitChange{CommitterAccountID: authA, RolesBefore: room(authA), OtherProposals: 1}, CommitAuthority{}, false},
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

// A group without roles takes no Commit from anyone, leaf 0 included: no
// update, Add, Remove (signed or not), re-seat, or roles set on it. Received,
// each is an unauthorized Commit naming its committer.
func TestJudgeReceived_AGroupWithoutRolesTakesNoCommit(t *testing.T) {
	abc := []string{authA, authB, authC}
	signed := CommitAuthority{Evidence: fixedEvidence{authorized: []int{0}}}
	for name, tc := range map[string]struct {
		change CommitChange
		auth   CommitAuthority
	}{
		"an update by leaf 0":      {CommitChange{CommitterAccountID: authA, Before: abc}, CommitAuthority{}},
		"an add by leaf 0":         {CommitChange{CommitterAccountID: authA, Added: []string{authD}, Before: abc}, CommitAuthority{}},
		"a remove by leaf 0":       {CommitChange{CommitterAccountID: authA, Removed: []string{authC}, Before: abc}, CommitAuthority{}},
		"a signed remove":          {CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc}, signed},
		"the committer's own leaf": {CommitChange{CommitterAccountID: authB, Removed: []string{authB}, Before: abc}, CommitAuthority{}},
		"a re-seat":                {CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Added: []string{authC}, Before: abc}, CommitAuthority{}},
		"a migration by leaf 0":    {CommitChange{CommitterAccountID: authA, Before: abc, RolesChange: RolesSet, RolesAfter: room(authA)}, CommitAuthority{}},
		"a DM marking":             {CommitChange{CommitterAccountID: authA, Before: []string{authA, authB}, RolesChange: RolesSet, RolesAfter: &Roles{Kind: RolesKindDM}}, CommitAuthority{}},
	} {
		err := JudgeReceived(tc.change, tc.auth)
		var refused *UnauthorizedCommitError
		if !errors.As(err, &refused) || refused.CommitterAccountID != tc.change.CommitterAccountID ||
			refused.Reason != reasonNoRoles {
			t.Fatalf("%s: JudgeReceived = %v", name, err)
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
	inRoom := func(c CommitChange) CommitChange { c.RolesBefore = room(authA, authB); c.Before = abc; return c }
	for name, tc := range map[string]struct {
		plan     CommitPlan
		change   CommitChange
		evidence RemovalEvidence
		want     error
	}{
		"an update": {CommitPlan{}, inRoom(CommitChange{CommitterAccountID: authC}), nil, nil},
		"an automated add": {CommitPlan{}, inRoom(CommitChange{CommitterAccountID: authB, Added: []string{authD}}), nil,
			ErrCommitUnauthorized},
		"an add a person asked for by an admin": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authB, Added: []string{authD}, Epoch: 2}), nil, nil},
		"an add a person asked for by a plain member of a room": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authC, Added: []string{authD}, Epoch: 2}), nil, ErrCommitUnauthorized},
		"the permit's word is no longer authority": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authC, Removed: []string{authB}}), nil, ErrCommitUnauthorized},
		"a remove a signed statement covers, by automation": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authC, Removed: []string{authB}}), fixedEvidence{authorized: []int{0}}, nil},
		"a statement that does not verify refuses the build": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authA, Removed: []string{authC}}), fixedEvidence{invalid: 1},
			ErrStatementUnverified},
		"an admin's remove, asked for": {CommitPlan{UserInitiated: true},
			inRoom(CommitChange{CommitterAccountID: authB, Removed: []string{authC}}), nil, nil},
		"an admin's remove, not asked for": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authB, Removed: []string{authC}}), nil, ErrCommitUnauthorized},
		"an owner's roles change needs a person": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authA, RolesChange: RolesSet, RolesAfter: room(authB)}), nil,
			ErrCommitUnauthorized},
		"a rejoin (R2)": {CommitPlan{},
			inRoom(CommitChange{CommitterAccountID: authC, Removed: []string{authB}, Added: []string{authB}}), nil, nil},
		"an update on a group without roles": {CommitPlan{},
			CommitChange{CommitterAccountID: authA, Before: abc}, nil, ErrGroupWithoutRoles},
		"an add by leaf 0 of a group without roles, asked for": {CommitPlan{UserInitiated: true},
			CommitChange{CommitterAccountID: authA, Added: []string{authD}, Before: abc}, nil, ErrGroupWithoutRoles},
		"a signed remove on a group without roles": {CommitPlan{},
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}, Before: abc},
			fixedEvidence{authorized: []int{0}}, ErrGroupWithoutRoles},
		"a migration on a group without roles": {CommitPlan{UserInitiated: true},
			CommitChange{CommitterAccountID: authA, Before: abc, RolesChange: RolesSet, RolesAfter: room(authA)},
			nil, ErrGroupWithoutRoles},
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
