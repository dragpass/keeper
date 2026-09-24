package chatstate

import (
	"errors"
	"testing"
)

const (
	authA = "a1111111-1111-4111-8111-111111111111"
	authB = "b2222222-2222-4222-8222-222222222222"
	authC = "c3333333-3333-4333-8333-333333333333"
)

func TestJudgeReceived_TheRules(t *testing.T) {
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
		"R3: a departure a permit names": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}},
			CommitAuthority{PendingRemovals: []string{authC}}, true},
		"R3b: the signed member set no longer holds it": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}},
			CommitAuthority{CommitMembers: []string{authA, authB}, CommitMembersKnown: true}, true},
		"a same-set remove": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}},
			CommitAuthority{CommitMembers: []string{authA, authB, authC}, CommitMembersKnown: true}, false},
		"a remove with no evidence at all": {
			CommitChange{CommitterAccountID: authB, Removed: []string{authC}}, CommitAuthority{}, false},
		// 임시, 정책 미충족 (Q3): no server statement is authority for an Add,
		// so a received Add stands on its leaf and trust checks alone.
		"an add, whatever the signed member set says": {
			CommitChange{CommitterAccountID: authA, Added: []string{authC}},
			CommitAuthority{CommitMembers: []string{authA, authB}, CommitMembersKnown: true}, true},
		"an add with no evidence": {
			CommitChange{CommitterAccountID: authA, Added: []string{authC}}, CommitAuthority{}, true},
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

func TestRequireAuthorizedPlan_BuildRules(t *testing.T) {
	rec := &Record{RemovalLatch: []string{authB}}
	add := [][]byte{{1}}
	for name, tc := range map[string]struct {
		plan CommitPlan
		wm   ServerWatermark
		ok   bool
	}{
		"an update":                       {CommitPlan{}, ServerWatermark{}, true},
		"an automated add":                {CommitPlan{AddKeyPackages: add}, ServerWatermark{}, false},
		"an add a person asked for":       {CommitPlan{AddKeyPackages: add, UserInitiated: true}, ServerWatermark{}, true},
		"an automated remove of a member": {CommitPlan{RemoveAccountIDs: []string{authC}}, ServerWatermark{}, false},
		"a remove of a departure (R3)":    {CommitPlan{RemoveAccountIDs: []string{authC}}, ServerWatermark{PendingRemovals: []string{authC}}, true},
		"a remove of a latched departure": {CommitPlan{RemoveAccountIDs: []string{authB}}, ServerWatermark{}, true},
		"a remove a person asked for":     {CommitPlan{RemoveAccountIDs: []string{authC}, UserInitiated: true}, ServerWatermark{}, true},
		"a rejoin, its request verified":  {CommitPlan{Rejoin: []RejoinMember{{AccountID: authC}}}, ServerWatermark{}, true},
	} {
		err := requireAuthorizedPlan(tc.plan, rec, tc.wm)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrCommitUnauthorized)) {
			t.Fatalf("%s: requireAuthorizedPlan = %v", name, err)
		}
	}
}
