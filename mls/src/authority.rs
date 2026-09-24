// authority.rs — the MlsRules that decide which proposals a Commit may carry,
// and the framing that reports a Commit's shape to the Go side.
//
// # Go judges, Rust enforces
//
// The same split as the leaf gate. Whether a Commit's Removes are allowed
// (the committer removing its own account's leaf, a Remove paired with an Add
// of the same account, a removal the signed server statements name) is decided
// in Go, next to the permit and the record. mls-rs asks its MlsRules about
// every Commit it builds or processes, and only that answer can stop one. So
// the rules here do not judge anything on their own: they hold the Removes Go
// approved for one operation and refuse every other one.
//
// The resting state is `Enforce` with nothing approved: a Commit that removes
// anybody, or carries any proposal type but Add and Remove, is refused. Each
// operation widens it for its own call and narrows it again when it returns,
// so a caller that skips the Go step gets a refusal rather than an unjudged
// Remove.
//
// # Collect
//
// Go cannot judge a Commit it has not seen, and the collect pass of processing
// is where it sees one. `Collect` lets everything through for exactly that
// pass; the session reports what the Commit did and throws the group away.

use std::sync::{Arc, Mutex};

use mls_rs::group::proposal::Proposal;
use mls_rs::group::{CommitEffect, ReceivedMessage};
use mls_rs::group::{GroupContext, Roster};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle, ProposalSource,
};
use mls_rs::MlsRules;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::ProposalType;

use crate::gate::{self, Leaf};

/// The phrase every refusal by these rules carries. mls-rs turns an MlsRules
/// error into a string of its own, so this text is what the C ABI edge keys a
/// distinct status code on, as it does for the leaf gate's.
pub const NOT_AUTHORIZED: &str = "not authorized by the commit authority check";

/// One Remove the Go side approved: the leaf at `index` holding `identity`.
/// The identity is part of it so that an approval given for one account's leaf
/// cannot remove whatever occupies that index by the time the Commit runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalApproval {
    pub index: u32,
    pub identity: Vec<u8>,
}

#[derive(Clone, Default)]
enum Mode {
    /// Let every proposal through. Only the collect pass runs in this mode.
    Collect,
    /// Let through Adds (the leaf gate judges those) and the approved Removes.
    #[default]
    Enforce,
}

#[derive(Default)]
struct State {
    mode: Mode,
    removals: Vec<RemovalApproval>,
}

/// The rules every session is built with. Clones share one state, which is how
/// the session changes what the client it built will accept.
#[derive(Clone)]
pub struct AuthorityRules {
    encryption: EncryptionOptions,
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
pub enum AuthorityError {
    NotAuthorized,
    Poisoned,
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthorityError::NotAuthorized => write!(f, "commit was {NOT_AUTHORIZED}"),
            AuthorityError::Poisoned => f.write_str("commit authority state is poisoned"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl IntoAnyError for AuthorityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

impl AuthorityRules {
    pub fn new(encryption: EncryptionOptions) -> Self {
        Self {
            encryption,
            state: Arc::default(),
        }
    }

    /// Let everything through until the next `enforce`.
    pub fn collect(&self) -> Result<(), String> {
        self.set(Mode::Collect, Vec::new())
    }

    /// Let through Adds and exactly `removals`.
    pub fn enforce(&self, removals: Vec<RemovalApproval>) -> Result<(), String> {
        self.set(Mode::Enforce, removals)
    }

    fn set(&self, mode: Mode, removals: Vec<RemovalApproval>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "mls: commit authority state is poisoned".to_string())?;
        state.mode = mode;
        state.removals = removals;
        Ok(())
    }

    fn judge(
        &self,
        direction: CommitDirection,
        roster: &Roster,
        mut proposals: ProposalBundle,
    ) -> Result<ProposalBundle, AuthorityError> {
        let state = self.state.lock().map_err(|_| AuthorityError::Poisoned)?;
        if matches!(state.mode, Mode::Collect) {
            return Ok(proposals);
        }
        // Nothing this integration builds is by reference. A by-reference
        // proposal cached from somebody's Proposal message is dropped from our
        // own build rather than refused, so a stray one cannot stop this device
        // from committing (RFC 9420 §12.2 asks for exactly that when preparing).
        if direction == CommitDirection::Send {
            proposals.retain(|p| {
                Ok::<_, AuthorityError>(!matches!(p.source, ProposalSource::ByReference(_)))
            })?;
        }
        if proposals.custom_proposal_types().next().is_some()
            || proposals
                .proposal_types()
                .any(|t| t != ProposalType::ADD && t != ProposalType::REMOVE)
        {
            return Err(AuthorityError::NotAuthorized);
        }
        for remove in proposals.remove_proposals() {
            let index = remove.proposal.to_remove();
            let member = roster
                .member_with_index(index)
                .map_err(|_| AuthorityError::NotAuthorized)?;
            let identity = identity_bytes(&member.signing_identity);
            let approved = state
                .removals
                .iter()
                .any(|a| a.index == index && a.identity == identity);
            if !approved {
                return Err(AuthorityError::NotAuthorized);
            }
        }
        Ok(proposals)
    }
}

fn identity_bytes(identity: &SigningIdentity) -> Vec<u8> {
    identity
        .credential
        .as_basic()
        .map(|b| b.identifier.to_vec())
        .unwrap_or_default()
}

impl MlsRules for AuthorityRules {
    type Error = AuthorityError;

    fn filter_proposals(
        &self,
        direction: CommitDirection,
        _source: CommitSource,
        current_roster: &Roster,
        _context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        self.judge(direction, current_roster, proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &Roster,
        _new_context: &GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(CommitOptions::default())
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster,
        _current_context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(self.encryption)
    }
}

// ─── the shape of one Commit, as the collect pass saw it ───────────────────

/// What a processed Commit did, for the Go side to judge. `removed` carries
/// each removed leaf as the tree held it before the Commit (its index and
/// identity); `added` carries each Add's leaf with index 0, as a KeyPackage
/// has no place yet. `other` lists every proposal type that is neither.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitShape {
    pub is_commit: bool,
    pub committer: u32,
    pub removed: Vec<Leaf>,
    pub added: Vec<Leaf>,
    pub other: Vec<u16>,
    /// The Commit's authenticated data, which the committer signed with it.
    pub authenticated_data: Vec<u8>,
}

impl CommitShape {
    /// Read the shape off a processed message. `before` is the tree the Commit
    /// was applied to, which is where a removed leaf's identity still is.
    pub fn of(received: &ReceivedMessage, before: &[Leaf]) -> Self {
        let ReceivedMessage::Commit(commit) = received else {
            return Self::default();
        };
        let applied = match &commit.effect {
            CommitEffect::NewEpoch(e) => &e.applied_proposals,
            CommitEffect::Removed { new_epoch, .. } => &new_epoch.applied_proposals,
            CommitEffect::ReInit(_) => {
                return Self {
                    is_commit: true,
                    committer: commit.committer,
                    other: vec![ProposalType::RE_INIT.raw_value()],
                    authenticated_data: commit.authenticated_data.clone(),
                    ..Self::default()
                };
            }
        };
        let mut shape = Self {
            is_commit: true,
            committer: commit.committer,
            authenticated_data: commit.authenticated_data.clone(),
            ..Self::default()
        };
        for info in applied {
            match &info.proposal {
                Proposal::Add(add) => shape.added.push(Leaf::from_parts(
                    0,
                    add.signing_identity(),
                    &add.leaf_node_extensions(),
                )),
                Proposal::Remove(remove) => {
                    let index = remove.to_remove();
                    let leaf = before.iter().find(|l| l.index == index).cloned();
                    shape.removed.push(leaf.unwrap_or(Leaf {
                        index,
                        identity: Vec::new(),
                        signature_key: Vec::new(),
                        declaration: None,
                    }));
                }
                other => shape.other.push(other.proposal_type().raw_value()),
            }
        }
        shape
    }
}

/// `u8 is_commit`, `u32 committer`, the removed and added leaves each in the
/// framing of `gate::encode_leaves`, then `u32 count` and one `u16` per other
/// proposal type, then the authenticated data as `u32 length` and its bytes.
/// Big-endian throughout.
pub fn encode_shape(shape: &CommitShape) -> Vec<u8> {
    let mut out = vec![u8::from(shape.is_commit)];
    out.extend_from_slice(&shape.committer.to_be_bytes());
    out.extend(gate::encode_leaves(&shape.removed));
    out.extend(gate::encode_leaves(&shape.added));
    let count = u32::try_from(shape.other.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for t in &shape.other {
        out.extend_from_slice(&t.to_be_bytes());
    }
    let len = u32::try_from(shape.authenticated_data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&shape.authenticated_data);
    out
}

/// Removal approvals are framed as `u32 count` then, per entry, `u32 index`
/// and a length-prefixed identity, big-endian.
pub fn decode_removals(buf: &[u8]) -> Result<Vec<RemovalApproval>, &'static str> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        let end = at.checked_add(n).ok_or("removal list is truncated")?;
        let out = buf.get(at..end).ok_or("removal list is truncated")?;
        at = end;
        Ok(out)
    };
    let u32_of = |b: &[u8]| -> Result<u32, &'static str> {
        let arr: [u8; 4] = b.try_into().map_err(|_| "removal list is truncated")?;
        Ok(u32::from_be_bytes(arr))
    };
    let count = usize::try_from(u32_of(take(4)?)?).map_err(|_| "removal count does not fit")?;
    if count > gate::MAX_LEAVES {
        return Err("too many approved removals");
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let index = u32_of(take(4)?)?;
        let len = usize::try_from(u32_of(take(4)?)?).map_err(|_| "removal length does not fit")?;
        out.push(RemovalApproval {
            index,
            identity: take(len)?.to_vec(),
        });
    }
    if at != buf.len() {
        return Err("removal list has trailing bytes");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removals_decode_strictly() {
        let mut buf = 1u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(b"id");
        assert_eq!(
            decode_removals(&buf),
            Ok(vec![RemovalApproval {
                index: 7,
                identity: b"id".to_vec()
            }])
        );
        assert!(decode_removals(&buf[..buf.len() - 1]).is_err());
        let mut trailing = buf.clone();
        trailing.push(0);
        assert!(decode_removals(&trailing).is_err());
        assert_eq!(decode_removals(&0u32.to_be_bytes()), Ok(Vec::new()));
        assert!(decode_removals(&u32::MAX.to_be_bytes()).is_err());
    }
}
