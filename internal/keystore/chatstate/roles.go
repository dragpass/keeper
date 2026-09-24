// roles.go — the room roles a group carries in its GroupContext (design Q3
// phase 2) and the rules on them, the Go half of mls/src/roles.rs.
//
// The Rust rules enforce these from the authenticated group context for every
// Commit built or received. This file makes the same judgement first, so a
// refusal names the rule that failed (UnauthorizedCommitError.Reason) and the
// local build can refuse before anything is built. The two must agree; the
// golden vectors in roles_test.go are the ones roles.rs pins.
//
// The payload:
//
//	dragpass.chat.roles|1|room|<account_id>:<role>,<account_id>:<role>,...
//	dragpass.chat.roles|1|dm|
//
// Accounts are lowercase UUIDs sorted ascending, roles are owner or admin, a
// room lists exactly one owner, a DM lists nobody. Parsing is strict: a payload
// that does not re-encode to the same bytes is refused.

package chatstate

import (
	"errors"
	"slices"
	"strings"
)

const (
	rolesDomain  = "dragpass.chat.roles"
	rolesVersion = "1"

	RolesKindRoom = "room"
	RolesKindDM   = "dm"

	RoleOwner = "owner"
	RoleAdmin = "admin"
)

// Authority names which rules a group is judged by, as the status reports it.
const (
	// AuthorityRoles — a room whose roles are in the group context.
	AuthorityRoles = "roles"
	// AuthorityDM — a DM marked as one in the group context.
	AuthorityDM = "dm"
	// AuthorityLegacyTemporary — a group created before 0.0.55 carries no
	// roles. It is judged by the wave 4 rules, which rest partly on the
	// server's word (임시, 정책 미충족): an Add needs only a verified leaf,
	// and a Remove may rest on the member set the server signed (R3b).
	AuthorityLegacyTemporary = "legacy_temporary"
)

var errRolesMalformed = errors.New("chat state roles payload is malformed")

// Roles is a parsed roles payload. Admins is sorted and excludes the owner.
type Roles struct {
	Kind   string
	Owner  string
	Admins []string
}

// RoleEntry is one listed account and its role.
type RoleEntry struct {
	AccountID string
	Role      string
}

// ParseRoles reads a payload strictly.
func ParseRoles(payload []byte) (Roles, error) {
	parts := strings.Split(string(payload), "|")
	if len(parts) != 4 || parts[0] != rolesDomain || parts[1] != rolesVersion {
		return Roles{}, errRolesMalformed
	}
	var r Roles
	switch parts[2] {
	case RolesKindDM:
		if parts[3] != "" {
			return Roles{}, errRolesMalformed
		}
		r.Kind = RolesKindDM
	case RolesKindRoom:
		r.Kind = RolesKindRoom
		for _, entry := range strings.Split(parts[3], ",") {
			account, role, ok := strings.Cut(entry, ":")
			if !ok || !isLowerUUID(account) {
				return Roles{}, errRolesMalformed
			}
			switch {
			case role == RoleOwner && r.Owner == "":
				r.Owner = account
			case role == RoleAdmin:
				r.Admins = append(r.Admins, account)
			default:
				return Roles{}, errRolesMalformed
			}
		}
		if r.Owner == "" {
			return Roles{}, errRolesMalformed
		}
		slices.Sort(r.Admins)
	default:
		return Roles{}, errRolesMalformed
	}
	if string(r.Encode()) != string(payload) {
		return Roles{}, errRolesMalformed
	}
	return r, nil
}

// RolesFromEntries builds a room's roles from a list of entries, refusing a
// list that is not exactly one owner plus admins, each account once.
func RolesFromEntries(kind string, entries []RoleEntry) (Roles, error) {
	r := Roles{Kind: kind}
	seen := map[string]bool{}
	for _, e := range entries {
		if !isLowerUUID(e.AccountID) || seen[e.AccountID] {
			return Roles{}, errRolesMalformed
		}
		seen[e.AccountID] = true
		switch {
		case kind == RolesKindRoom && e.Role == RoleOwner && r.Owner == "":
			r.Owner = e.AccountID
		case kind == RolesKindRoom && e.Role == RoleAdmin:
			r.Admins = append(r.Admins, e.AccountID)
		default:
			return Roles{}, errRolesMalformed
		}
	}
	if kind == RolesKindRoom && r.Owner == "" {
		return Roles{}, errRolesMalformed
	}
	if kind != RolesKindRoom && kind != RolesKindDM {
		return Roles{}, errRolesMalformed
	}
	slices.Sort(r.Admins)
	return r, nil
}

// Encode writes the canonical payload.
func (r Roles) Encode() []byte {
	if r.Kind == RolesKindDM {
		return []byte(rolesDomain + "|" + rolesVersion + "|dm|")
	}
	entries := r.Entries()
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.AccountID + ":" + e.Role
	}
	return []byte(rolesDomain + "|" + rolesVersion + "|room|" + strings.Join(parts, ","))
}

// Entries lists the owner and the admins sorted by account.
func (r Roles) Entries() []RoleEntry {
	if r.Kind != RolesKindRoom {
		return []RoleEntry{}
	}
	out := []RoleEntry{{AccountID: r.Owner, Role: RoleOwner}}
	for _, a := range r.Admins {
		out = append(out, RoleEntry{AccountID: a, Role: RoleAdmin})
	}
	slices.SortFunc(out, func(a, b RoleEntry) int { return strings.Compare(a.AccountID, b.AccountID) })
	return out
}

// RoleOf is the account's role, or "" for a member or a DM.
func (r Roles) RoleOf(account string) string {
	switch {
	case r.Kind != RolesKindRoom:
		return ""
	case r.Owner == account:
		return RoleOwner
	case slices.Contains(r.Admins, account):
		return RoleAdmin
	}
	return ""
}

func (r Roles) equal(o Roles) bool {
	return r.Kind == o.Kind && r.Owner == o.Owner && slices.Equal(r.Admins, o.Admins)
}

func isLowerUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c < '0' || c > '9') && (c < 'a' || c > 'f'):
			return false
		}
	}
	return true
}

// RolesChangeKind is what a Commit's GroupContextExtensions proposal did.
type RolesChangeKind int

const (
	RolesUnchanged RolesChangeKind = iota
	RolesSet
	RolesDropped
	// RolesOtherExtension — the proposal changed an extension other than the
	// roles, which nothing here ever does.
	RolesOtherExtension
)

// holdsBefore reports whether account holds a leaf before the Commit.
func (c CommitChange) holdsBefore(account string) bool {
	return slices.Contains(c.Before, account)
}

// holdsAfter reports whether account holds a leaf after the Commit.
func (c CommitChange) holdsAfter(account string) bool {
	return c.leavesAfter(account) > 0
}

// leavesAfter is how many leaves account holds once the Commit is applied.
func (c CommitChange) leavesAfter(account string) int {
	count := func(list []string) int {
		n := 0
		for _, a := range list {
			if a == account {
				n++
			}
		}
		return n
	}
	before := count(c.Before)
	return before - min(count(c.Removed), before) + count(c.Added)
}

func (c CommitChange) accountsAfter() int {
	seen := map[string]bool{}
	for _, a := range append(slices.Clone(c.Before), c.Added...) {
		if !seen[a] && c.holdsAfter(a) {
			seen[a] = true
		}
	}
	return len(seen)
}

// effectiveRoles is what the Commit's Adds and Removes are judged against:
// the group's roles, or for the Commit that first sets a room's roles on a
// legacy group, the ones it sets (the migration).
func (c CommitChange) effectiveRoles() *Roles {
	return c.EffectiveRoles()
}

// EffectiveRoles is effectiveRoles for the rules outside this file (the
// succession rule, succession.go).
func (c CommitChange) EffectiveRoles() *Roles {
	if c.RolesBefore != nil {
		return c.RolesBefore
	}
	if c.RolesChange == RolesSet && c.RolesAfter != nil && c.RolesAfter.Kind == RolesKindRoom &&
		c.RolesAfter.Owner == c.CommitterAccountID && c.CreatorAccountID == c.CommitterAccountID {
		return c.RolesAfter
	}
	return nil
}

// judgeRoles is roles::check: the rules on Adds and on the roles themselves.
// "" means the Commit passes them.
func judgeRoles(c CommitChange) string {
	switch c.RolesChange {
	case RolesOtherExtension:
		return "the commit changes a group context extension other than the roles"
	case RolesDropped:
		if c.RolesBefore != nil {
			return "the commit drops the group's roles"
		}
	case RolesSet:
		if reason := judgeRolesChange(c); reason != "" {
			return reason
		}
	}
	// One active device per account (Q14, N1), judged on the whole candidate
	// tree the Commit leaves behind, as roles::check does: an existing
	// duplicate is not repaired, and no Commit that keeps it is accepted.
	for _, account := range append(slices.Clone(c.Before), c.Added...) {
		if account != "" && c.leavesAfter(account) > 1 {
			return "an account holds more than one leaf after the commit"
		}
	}
	roles := c.effectiveRoles()
	for _, account := range c.Added {
		if slices.Contains(c.Removed, account) {
			continue // R2
		}
		switch {
		case roles == nil:
		case roles.Kind == RolesKindDM:
			if c.Epoch != 0 {
				return "a DM adds nobody after it is created"
			}
		default:
			by := roles.RoleOf(c.CommitterAccountID)
			if by == "" {
				return "only the room's owner or an admin adds a member"
			}
			stale := c.Epoch != 0 && roles.RoleOf(account) != ""
			if stale && !(c.RolesChange == RolesSet && by == RoleOwner) {
				return "an added account still holds a role entry nobody reset"
			}
		}
	}
	if roles != nil && roles.Kind == RolesKindDM && c.accountsAfter() > 2 {
		return "a DM holds two accounts at most"
	}
	return ""
}

func judgeRolesChange(c CommitChange) string {
	after := *c.RolesAfter
	before := c.RolesBefore
	switch {
	case before == nil && after.Kind == RolesKindRoom:
		// roles::check_roles_change: leaf 0 is the room's creator, which is
		// the one thing a legacy room's authenticated state says about who
		// owns it; the server's owner check is the other half (수용한 한계).
		if c.CommitterAccountID != after.Owner || c.CreatorAccountID != c.CommitterAccountID {
			return "only the room's creator, as its owner, sets its first roles"
		}
	case before == nil && after.Kind == RolesKindDM:
		distinct := map[string]bool{}
		for _, a := range c.Before {
			distinct[a] = true
		}
		if len(distinct) > 2 {
			return "a group of more than two accounts is not a DM"
		}
	case before.Kind == RolesKindDM:
		return "a DM's roles never change"
	case after.Kind == RolesKindDM:
		return "a room never becomes a DM"
	default:
		if before.RoleOf(c.CommitterAccountID) != RoleOwner && !c.isOwnerlessClaim(*before, after) {
			return "only the room's owner changes its roles"
		}
	}
	if after.Kind == RolesKindRoom {
		for _, e := range after.Entries() {
			if !c.holdsAfter(e.AccountID) {
				return "a role entry names an account with no leaf after the commit"
			}
		}
	}
	return ""
}

// isOwnerlessClaim is roles::is_ownerless_claim: an admin (or, with no live
// admin, any member) takes over a room whose owner holds no leaf, changing
// nothing but the owner.
func (c CommitChange) isOwnerlessClaim(before, after Roles) bool {
	claimer := c.CommitterAccountID
	if claimer == "" || c.holdsBefore(before.Owner) {
		return false
	}
	var live []string
	for _, a := range before.Admins {
		if c.holdsBefore(a) {
			live = append(live, a)
		}
	}
	mayClaim := slices.Contains(live, claimer)
	if len(live) == 0 {
		mayClaim = c.holdsBefore(claimer)
	}
	expected := Roles{Kind: RolesKindRoom, Owner: claimer,
		Admins: slices.DeleteFunc(slices.Clone(before.Admins), func(a string) bool { return a == claimer })}
	return mayClaim && after.equal(expected)
}

// roleMayRemove reports whether committer's role in roles lets it remove
// account: the owner anyone, an admin anyone but the owner and the admins.
func roleMayRemove(roles *Roles, committer, account string) bool {
	if roles == nil || roles.Kind != RolesKindRoom {
		return false
	}
	switch roles.RoleOf(committer) {
	case RoleOwner:
		return true
	case RoleAdmin:
		return roles.RoleOf(account) == ""
	}
	return false
}

// AuthorityOf names the rules a group with this roles payload is judged by.
func AuthorityOf(roles *Roles) string {
	switch {
	case roles == nil:
		return AuthorityLegacyTemporary
	case roles.Kind == RolesKindDM:
		return AuthorityDM
	}
	return AuthorityRoles
}
