// roles.rs — the room roles a group carries in its GroupContext (design Q3
// phase 2), and the rules that decide who may change the group.
//
// # Why the group context
//
// A role the server keeps is the server's word, and policy 5 says no Add or
// Remove may rest on that alone. A GroupContext extension is part of the
// authenticated group state: every member holds the same bytes, a change to it
// is a proposal inside a signed Commit, and the key schedule binds it. So the
// rules below read the roles from the context the Commit is applied to, never
// from anything the caller hands in.
//
// # The payload
//
//     dragpass.chat.roles|1|room|<account_id>:<role>,<account_id>:<role>,...
//     dragpass.chat.roles|1|dm|
//
// Accounts are lowercase UUIDs sorted ascending, roles are `owner` or `admin`,
// a room lists exactly one owner, a DM lists nobody. Anyone holding a leaf is a
// member without being listed. Parsing is strict: a payload that does not
// re-encode to the same bytes is refused, so two members can never read one
// payload two ways. The Go side (chatstate/roles.go) holds the same format and
// the same golden vectors.
//
// # Build and receive are one judgement
//
// `check` runs from `AuthorityRules::filter_proposals`, which mls-rs calls for
// a Commit this device builds and for every Commit it processes. A Commit this
// device would refuse on receipt is therefore never built here either.
//
// Removes are not judged here beyond the DM and stale-entry shapes: whether a
// Remove is allowed depends on signed statements only Go can verify, so Go
// approves each one (authority.rs) and these rules add the role-based limits
// on Adds and on the roles themselves.

use mls_rs::extension::ExtensionType;
use mls_rs::group::Roster;
use mls_rs::mls_rules::{CommitSource, ProposalBundle};
use mls_rs::ExtensionList;

pub const ROLES_EXTENSION: u16 = 0xF0D1;

const DOMAIN: &str = "dragpass.chat.roles";
const VERSION: &str = "1";

const CREDENTIAL_DOMAIN: &str = "dragpass.mls.credential";
const CREDENTIAL_VERSION: &str = "1";

pub fn roles_extension_type() -> ExtensionType {
    ExtensionType::new(ROLES_EXTENSION)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Roles {
    Dm,
    Room { owner: String, admins: Vec<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
}

fn is_lower_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// The account a DragPass device identity names, or None for any identity
/// that is not one. Mirrors mls.ParseCredentialIdentity on the Go side.
pub fn account_of(identity: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(identity).ok()?;
    let parts: Vec<&str> = s.split('|').collect();
    match parts.as_slice() {
        [domain, version, account, device]
            if *domain == CREDENTIAL_DOMAIN
                && *version == CREDENTIAL_VERSION
                && is_lower_uuid(account)
                && is_lower_uuid(device) =>
        {
            Some((*account).to_string())
        }
        _ => None,
    }
}

impl Roles {
    pub fn parse(payload: &[u8]) -> Result<Self, &'static str> {
        let text = std::str::from_utf8(payload).map_err(|_| "roles payload is not UTF-8")?;
        let parts: Vec<&str> = text.split('|').collect();
        let [domain, version, kind, entries] = parts.as_slice() else {
            return Err("roles payload has the wrong number of slots");
        };
        if *domain != DOMAIN || *version != VERSION {
            return Err("roles payload has an unknown domain or version");
        }
        let roles = match *kind {
            "dm" if entries.is_empty() => Roles::Dm,
            "dm" => return Err("a DM carries no roles"),
            "room" => {
                let mut owner = None;
                let mut admins = Vec::new();
                for entry in entries.split(',') {
                    let (account, role) = entry
                        .split_once(':')
                        .ok_or("roles entry is not account:role")?;
                    if !is_lower_uuid(account) {
                        return Err("roles entry names no account");
                    }
                    match role {
                        "owner" if owner.is_none() => owner = Some(account.to_string()),
                        "owner" => return Err("a room has one owner"),
                        "admin" => admins.push(account.to_string()),
                        _ => return Err("roles entry has an unknown role"),
                    }
                }
                let owner = owner.ok_or("a room has one owner")?;
                admins.sort();
                Roles::Room { owner, admins }
            }
            _ => return Err("roles payload has an unknown kind"),
        };
        if roles.encode() != payload {
            return Err("roles payload is not canonical");
        }
        Ok(roles)
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Roles::Dm => format!("{DOMAIN}|{VERSION}|dm|").into_bytes(),
            Roles::Room { owner, admins } => {
                let mut entries: Vec<(String, &str)> =
                    admins.iter().map(|a| (a.clone(), "admin")).collect();
                entries.push((owner.clone(), "owner"));
                entries.sort();
                let joined: Vec<String> = entries.iter().map(|(a, r)| format!("{a}:{r}")).collect();
                format!("{DOMAIN}|{VERSION}|room|{}", joined.join(",")).into_bytes()
            }
        }
    }

    pub fn role_of(&self, account: &str) -> Option<Role> {
        match self {
            Roles::Dm => None,
            Roles::Room { owner, .. } if owner == account => Some(Role::Owner),
            Roles::Room { admins, .. } if admins.iter().any(|a| a == account) => Some(Role::Admin),
            Roles::Room { .. } => None,
        }
    }

    fn listed(&self) -> Vec<&str> {
        match self {
            Roles::Dm => Vec::new(),
            Roles::Room { owner, admins } => std::iter::once(owner.as_str())
                .chain(admins.iter().map(String::as_str))
                .collect(),
        }
    }
}

/// The roles an extension list carries: None when it has none, an error when
/// the payload does not parse (which refuses the Commit carrying it).
pub fn roles_in(extensions: &ExtensionList) -> Result<Option<Roles>, &'static str> {
    match extensions.get(roles_extension_type()) {
        None => Ok(None),
        Some(ext) => Roles::parse(ext.extension_data()).map(Some),
    }
}

/// True when both lists hold the same extensions once 0xF0D1 is set aside.
pub fn same_except_roles(a: &ExtensionList, b: &ExtensionList) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.remove(roles_extension_type());
    b.remove(roles_extension_type());
    let mut a: Vec<_> = a.iter().cloned().collect();
    let mut b: Vec<_> = b.iter().cloned().collect();
    a.sort_by_key(|e| e.extension_type());
    b.sort_by_key(|e| e.extension_type());
    a == b
}

/// What one Commit asks for, in accounts. Every account of the group it is
/// applied to is counted by leaf, so "holds a leaf after" can be told from
/// "had one of two leaves removed".
pub struct Change<'a> {
    pub committer: Option<String>,
    /// The account holding leaf 0, the leaf of whoever created the group.
    pub creator: Option<String>,
    pub epoch: u64,
    pub before: &'a [Option<String>],
    pub removed: Vec<Option<String>>,
    pub added: Vec<Option<String>>,
    pub roles_before: Option<Roles>,
    /// None: no GroupContextExtensions proposal. Some(None): one that drops
    /// the roles. Some(Some(r)): one that sets r.
    pub roles_after: Option<Option<Roles>>,
}

impl Change<'_> {
    fn holds_before(&self, account: &str) -> bool {
        self.before.iter().any(|a| a.as_deref() == Some(account))
    }

    fn holds_after(&self, account: &str) -> bool {
        self.leaves_after(account) > 0
    }

    /// How many leaves the account holds once the Commit is applied.
    fn leaves_after(&self, account: &str) -> usize {
        let count = |list: &[Option<String>]| {
            list.iter()
                .filter(|a| a.as_deref() == Some(account))
                .count()
        };
        let before = count(self.before);
        before - count(&self.removed).min(before) + count(&self.added)
    }

    fn accounts_after(&self) -> usize {
        let mut all: Vec<&str> = self
            .before
            .iter()
            .chain(self.added.iter())
            .filter_map(|a| a.as_deref())
            .collect();
        all.sort_unstable();
        all.dedup();
        all.into_iter().filter(|a| self.holds_after(a)).count()
    }

    fn is_removed(&self, account: &str) -> bool {
        self.removed.iter().any(|a| a.as_deref() == Some(account))
    }
}

/// Why a Commit breaks the rules, as a condition and never a value.
pub type Refusal = &'static str;

/// The roles a Commit's Adds and Removes are judged against: the group's, or
/// for the Commit that first sets a room's roles on a legacy group, the ones
/// it sets (the migration, design §0.3 Q3).
pub fn effective_roles(change: &Change<'_>) -> Option<Roles> {
    match (&change.roles_before, &change.roles_after) {
        (Some(r), _) => Some(r.clone()),
        (None, Some(Some(r @ Roles::Room { owner, .. })))
            if change.committer.as_deref() == Some(owner.as_str())
                && change.creator == change.committer =>
        {
            Some(r.clone())
        }
        _ => None,
    }
}

/// The role rules on Adds and on the roles themselves (the file comment).
pub fn check(change: &Change<'_>) -> Result<(), Refusal> {
    if let Some(after) = &change.roles_after {
        check_roles_change(change, after.as_ref())?;
    }
    // One active device per account (Q14, N1), judged on the whole candidate
    // tree the Commit leaves behind: every account in it holds at most one
    // leaf. A group that already held two leaves of an account before this
    // rule takes no Commit that keeps both; nothing here repairs it, and its
    // way on is a new group.
    if change
        .before
        .iter()
        .chain(change.added.iter())
        .flatten()
        .any(|a| change.leaves_after(a) > 1)
    {
        return Err("an account holds more than one leaf after the commit");
    }
    let roles = effective_roles(change);
    for added in &change.added {
        let account = added.as_deref();
        // R2: the account is also removed here — a replace or a rejoin.
        if account.is_some_and(|a| change.is_removed(a)) {
            continue;
        }
        match &roles {
            None => {}
            Some(Roles::Dm) => {
                if change.epoch != 0 {
                    return Err("a DM adds nobody after it is created");
                }
            }
            Some(r @ Roles::Room { .. }) => {
                let by = change.committer.as_deref().and_then(|c| r.role_of(c));
                if by.is_none() {
                    return Err("only the room's owner or an admin adds a member");
                }
                // At epoch 0 the entries are the ones the creator just set
                // for the members its first Commit brings in.
                let stale = change.epoch != 0 && account.is_some_and(|a| r.role_of(a).is_some());
                let owner_sets_roles =
                    matches!(change.roles_after, Some(Some(_))) && by == Some(Role::Owner);
                if stale && !owner_sets_roles {
                    return Err("an added account still holds a role entry nobody reset");
                }
            }
        }
    }
    if matches!(roles, Some(Roles::Dm)) && change.accounts_after() > 2 {
        return Err("a DM holds two accounts at most");
    }
    Ok(())
}

fn check_roles_change(change: &Change<'_>, after: Option<&Roles>) -> Result<(), Refusal> {
    let committer = change.committer.as_deref();
    let Some(after) = after else {
        return match change.roles_before {
            Some(_) => Err("a group's roles are never dropped"),
            None => Ok(()),
        };
    };
    match (&change.roles_before, after) {
        (None, Roles::Room { owner, .. }) => {
            // A legacy room has no roles to ask, so the migration rests on the
            // one thing its authenticated state says about ownership: leaf 0
            // is the leaf of the account that created the room, and rooms were
            // created by their owner. The server's check that the committer is
            // its owner is the other half, taken once (수용한 한계).
            if committer != Some(owner.as_str()) || change.creator.as_deref() != committer {
                return Err("only the room's creator, as its owner, sets its first roles");
            }
        }
        (None, Roles::Dm) => {
            let mut accounts: Vec<&str> =
                change.before.iter().filter_map(|a| a.as_deref()).collect();
            accounts.sort_unstable();
            accounts.dedup();
            if accounts.len() > 2 {
                return Err("a group of more than two accounts is not a DM");
            }
        }
        (Some(Roles::Dm), _) => return Err("a DM's roles never change"),
        (Some(Roles::Room { .. }), Roles::Dm) => return Err("a room never becomes a DM"),
        (Some(before @ Roles::Room { owner, admins }), next @ Roles::Room { .. }) => {
            let by = committer.and_then(|c| before.role_of(c));
            if by != Some(Role::Owner) && !is_ownerless_claim(change, owner, admins, next) {
                return Err("only the room's owner changes its roles");
            }
        }
    }
    if let Roles::Room { .. } = after {
        if after.listed().iter().any(|a| !change.holds_after(a)) {
            return Err("a role entry names an account with no leaf after the commit");
        }
    }
    Ok(())
}

/// The one change a non-owner may make: take over a room whose owner holds no
/// leaf any more (removed with the organization's signed statement). An admin
/// may claim it; only when no admin holds a leaf may any member. The claim
/// changes nothing but the owner.
fn is_ownerless_claim(change: &Change<'_>, owner: &str, admins: &[String], next: &Roles) -> bool {
    let Some(claimer) = change.committer.as_deref() else {
        return false;
    };
    if change.holds_before(owner) {
        return false;
    }
    let live_admins: Vec<&String> = admins.iter().filter(|a| change.holds_before(a)).collect();
    let may_claim = if live_admins.is_empty() {
        change.holds_before(claimer)
    } else {
        live_admins.iter().any(|a| a.as_str() == claimer)
    };
    let expected = Roles::Room {
        owner: claimer.to_string(),
        admins: admins
            .iter()
            .filter(|a| a.as_str() != claimer)
            .cloned()
            .collect(),
    };
    may_claim && *next == expected
}

/// Read one proposal bundle into a Change: the committer and every removed
/// and added leaf as accounts, and the roles before and after.
pub fn change_of<'a>(
    source: &CommitSource,
    roster: &Roster,
    context: &mls_rs::group::GroupContext,
    proposals: &ProposalBundle,
    before: &'a [Option<String>],
) -> Result<Change<'a>, Refusal> {
    let committer = match source {
        CommitSource::ExistingMember(m) => identity_account(&m.signing_identity),
        CommitSource::NewMember(_) => None,
    };
    let mut removed = Vec::new();
    for remove in proposals.remove_proposals() {
        let member = roster
            .member_with_index(remove.proposal.to_remove())
            .map_err(|_| "a remove names no leaf of the group")?;
        removed.push(identity_account(&member.signing_identity));
    }
    let added = proposals
        .add_proposals()
        .iter()
        .map(|a| identity_account(a.proposal.signing_identity()))
        .collect();
    let roles_before = roles_in(&context.extensions)?;
    let gces = proposals.group_context_ext_proposals();
    if gces.len() > 1 {
        return Err("a commit carries one group context change at most");
    }
    let roles_after = match gces.first() {
        None => None,
        Some(g) => {
            if !same_except_roles(&context.extensions, &g.proposal) {
                return Err("a group context change touches more than the roles");
            }
            Some(roles_in(&g.proposal)?)
        }
    };
    let creator = roster
        .member_with_index(0)
        .ok()
        .and_then(|m| identity_account(&m.signing_identity));
    Ok(Change {
        committer,
        creator,
        epoch: context.epoch,
        before,
        removed,
        added,
        roles_before,
        roles_after,
    })
}

fn identity_account(identity: &mls_rs::identity::SigningIdentity) -> Option<String> {
    identity
        .credential
        .as_basic()
        .and_then(|b| account_of(&b.identifier))
}

/// Every account of a roster, one entry per leaf.
pub fn roster_accounts(roster: &Roster) -> Vec<Option<String>> {
    roster
        .members_iter()
        .map(|m| identity_account(&m.signing_identity))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0a000000-0000-4000-8000-000000000001";
    const B: &str = "0b000000-0000-4000-8000-000000000002";
    const C: &str = "0c000000-0000-4000-8000-000000000003";

    fn room(owner: &str, admins: &[&str]) -> Roles {
        let mut admins: Vec<String> = admins.iter().map(|a| a.to_string()).collect();
        admins.sort();
        Roles::Room {
            owner: owner.to_string(),
            admins,
        }
    }

    fn acct(a: &str) -> Option<String> {
        Some(a.to_string())
    }

    #[test]
    fn payload_round_trips_and_is_strict() {
        let r = room(B, &[C, A]);
        let bytes = r.encode();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!("dragpass.chat.roles|1|room|{A}:admin,{B}:owner,{C}:admin")
        );
        assert_eq!(Roles::parse(&bytes), Ok(r));
        assert_eq!(Roles::parse(b"dragpass.chat.roles|1|dm|"), Ok(Roles::Dm));
        for bad in [
            format!("dragpass.chat.roles|1|room|{B}:owner,{A}:admin"),
            format!("dragpass.chat.roles|1|room|{A}:owner,{B}:owner"),
            format!("dragpass.chat.roles|1|room|{A}:admin"),
            format!("dragpass.chat.roles|1|room|{A}:member,{B}:owner"),
            format!("dragpass.chat.roles|2|room|{A}:owner"),
            format!("dragpass.chat.roles|1|dm|{A}:owner"),
            format!("dragpass.chat.roles|1|room|{A}:owner|"),
            format!("dragpass.chat.roles|1|room|{}:owner", A.to_uppercase()),
        ] {
            assert!(Roles::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn identity_account_is_strict() {
        let id = format!("dragpass.mls.credential|1|{A}|{B}");
        assert_eq!(account_of(id.as_bytes()), Some(A.to_string()));
        assert_eq!(account_of(b"alice"), None);
        assert_eq!(
            account_of(format!("dragpass.mls.credential|2|{A}|{B}").as_bytes()),
            None
        );
    }

    fn change<'a>(
        before: &'a [Option<String>],
        committer: &str,
        roles: Option<Roles>,
    ) -> Change<'a> {
        Change {
            committer: acct(committer),
            creator: before.first().cloned().flatten(),
            epoch: 5,
            before,
            removed: Vec::new(),
            added: Vec::new(),
            roles_before: roles,
            roles_after: None,
        }
    }

    #[test]
    fn a_room_member_cannot_add_but_an_admin_can() {
        let before = [acct(A), acct(B), acct(C)];
        let mut c = change(&before, C, Some(room(A, &[B])));
        c.added = vec![acct("0d000000-0000-4000-8000-000000000004")];
        assert!(check(&c).is_err());
        c.committer = acct(B);
        assert!(check(&c).is_ok());
    }

    #[test]
    fn only_the_owner_changes_roles() {
        let before = [acct(A), acct(B), acct(C)];
        let mut c = change(&before, B, Some(room(A, &[B])));
        c.roles_after = Some(Some(room(B, &[A])));
        assert!(check(&c).is_err());
        c.committer = acct(A);
        assert!(check(&c).is_ok());
    }

    #[test]
    fn roles_never_drop_and_a_dm_never_changes() {
        let before = [acct(A), acct(B)];
        let mut c = change(&before, A, Some(room(A, &[])));
        c.roles_after = Some(None);
        assert!(check(&c).is_err());
        let mut d = change(&before, A, Some(Roles::Dm));
        d.roles_after = Some(Some(room(A, &[])));
        assert!(check(&d).is_err());
    }

    #[test]
    fn a_dm_adds_only_at_create_and_never_a_third() {
        let before = [acct(A)];
        let mut c = change(&before, A, Some(Roles::Dm));
        c.added = vec![acct(B)];
        assert!(check(&c).is_err(), "after create");
        c.epoch = 0;
        assert!(check(&c).is_ok());
        let two = [acct(A), acct(B)];
        let mut third = change(&two, A, Some(Roles::Dm));
        third.epoch = 0;
        third.added = vec![acct(C)];
        assert!(check(&third).is_err());
        let mut rejoin = change(&two, A, Some(Roles::Dm));
        rejoin.removed = vec![acct(B)];
        rejoin.added = vec![acct(B)];
        assert!(check(&rejoin).is_ok(), "R2 re-seat");
    }

    #[test]
    fn a_legacy_room_migrates_only_by_its_creator_as_owner() {
        let before = [acct(A), acct(B)];
        let mut c = change(&before, B, None);
        c.roles_after = Some(Some(room(A, &[])));
        assert!(check(&c).is_err(), "not the one it names");
        c.roles_after = Some(Some(room(B, &[])));
        assert!(check(&c).is_err(), "not the creator");
        c.committer = acct(A);
        c.roles_after = Some(Some(room(A, &[])));
        assert!(check(&c).is_ok());
        assert_eq!(effective_roles(&c), Some(room(A, &[])));
    }

    #[test]
    fn an_ownerless_room_is_claimed_by_an_admin_only() {
        // The owner A holds no leaf any more.
        let before = [acct(B), acct(C)];
        let mut c = change(&before, C, Some(room(A, &[B])));
        c.roles_after = Some(Some(room(C, &[B])));
        assert!(check(&c).is_err(), "a member while an admin is live");
        c.committer = acct(B);
        c.roles_after = Some(Some(room(B, &[])));
        assert!(check(&c).is_ok());
        c.roles_after = Some(Some(room(B, &[C])));
        assert!(check(&c).is_err(), "the claim changes only the owner");
        let live = [acct(A), acct(B)];
        let mut early = change(&live, B, Some(room(A, &[B])));
        early.roles_after = Some(Some(room(B, &[])));
        assert!(check(&early).is_err(), "the owner still holds a leaf");
    }

    #[test]
    fn a_stale_role_entry_does_not_come_back_with_an_add() {
        let before = [acct(A), acct(B)];
        let mut c = change(&before, B, Some(room(A, &[B, C])));
        c.added = vec![acct(C)];
        assert!(check(&c).is_err());
    }

    // One active device per account, in every kind of group: a second leaf of
    // an account in the tree comes in only in place of the one it holds.
    #[test]
    fn an_account_that_holds_a_leaf_is_added_again_only_in_its_place() {
        let before = [acct(A), acct(B)];
        for roles in [None, Some(room(A, &[])), Some(Roles::Dm)] {
            let mut c = change(&before, A, roles);
            c.epoch = 0;
            c.added = vec![acct(B)];
            assert!(check(&c).is_err());
            c.removed = vec![acct(B)];
            assert!(check(&c).is_ok());
        }
    }

    // Q14: one device per account is judged on the tree after the Commit, not
    // on the add list alone.
    #[test]
    fn an_account_holds_one_leaf_after_the_commit() {
        for roles in [None, Some(room(A, &[])), Some(Roles::Dm)] {
            let before = [acct(A)];
            let mut two_new = change(&before, A, roles.clone());
            two_new.epoch = 0;
            two_new.added = vec![acct(B), acct(B)];
            assert!(check(&two_new).is_err(), "two new leaves of one account");
            two_new.added = vec![acct(B)];
            assert!(check(&two_new).is_ok(), "one new leaf");

            let seated = [acct(A), acct(B)];
            let mut reseat_two = change(&seated, A, roles);
            reseat_two.epoch = 0;
            reseat_two.removed = vec![acct(B)];
            reseat_two.added = vec![acct(B), acct(B)];
            assert!(
                check(&reseat_two).is_err(),
                "a re-seat that brings two leaves"
            );
        }
    }

    // N1: a tree that already holds two leaves of an account takes no Commit
    // that keeps both, an empty one included; one that removes one of them
    // is accepted.
    #[test]
    fn a_tree_that_already_holds_two_leaves_of_an_account_takes_no_commit_that_keeps_them() {
        let before = [acct(A), acct(B), acct(B)];
        let update = change(&before, A, None);
        assert!(check(&update).is_err(), "an update over the duplicate");
        let mut add = change(&before, A, None);
        add.added = vec![acct(C)];
        assert!(check(&add).is_err(), "an unrelated add");
        let mut fix = change(&before, A, None);
        fix.removed = vec![acct(B)];
        assert!(check(&fix).is_ok(), "removing one of the two");
    }

    #[test]
    fn role_entries_must_hold_a_leaf_after() {
        let before = [acct(A), acct(B)];
        let mut c = change(&before, A, Some(room(A, &[])));
        c.roles_after = Some(Some(room(A, &[C])));
        assert!(check(&c).is_err());
    }
}
