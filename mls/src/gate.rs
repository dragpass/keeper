// gate.rs — the IdentityProvider that decides which leaves this device lets
// into a group, and the byte framing the Go side uses to talk to it.
//
// # Go verifies, Rust enforces
//
// The checks that make a leaf trustworthy (the account key pin, the RSA-PSS
// signature on the leaf declaration, the declaration naming this very key) live
// in Go, next to the pin store. mls-rs, on the other hand, asks its
// IdentityProvider about every leaf it is about to accept, and only that answer
// can stop a Commit or a Welcome from being applied. So the provider here does
// not judge a leaf on its own merits. It holds a list of signing identities the
// Go side has already approved and refuses every other one.
//
// That list is only ever filled for one operation at a time. The resting state
// is `Enforce` with nothing approved, which admits this device alone. Each
// group operation widens it to the members already in the group plus what was
// approved for that one operation, and narrows it again when the operation
// returns, so a caller that skips the Go step gets a refusal rather than an
// unverified member.
//
// # Collect
//
// Go cannot approve a leaf it has not seen, and mls-rs offers no way to list a
// Commit's or a Welcome's new leaves without processing it. `Collect` admits
// every leaf for exactly that first pass; the session copies what the pass
// produced and throws the resulting group away. Nothing the collect pass
// accepted is ever kept.

use std::sync::{Arc, Mutex};

use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::{CredentialType, SigningIdentity};
use mls_rs::time::MlsTime;
use mls_rs::ExtensionList;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

/// The LeafNode extension that carries this device's leaf declaration.
///
/// RFC 9420 §17.3 reserves 0xF000–0xFFFF for private use, so a value there
/// cannot collide with a registered extension and will never be assigned by
/// IANA. The number itself carries no meaning; 0xF0D0 was picked so it does not
/// look like a GREASE value (§13.5 reserves 0x?A?A) to anyone reading a dump.
///
/// It is a LeafNode extension rather than a KeyPackage extension because the
/// leaf's own key signs it and it stays in the ratchet tree: whoever Adds the
/// member, whoever processes that Commit and whoever joins later can all read
/// and check it, and a server that strips or edits it breaks the leaf
/// signature.
pub const LEAF_DECLARATION_EXTENSION: u16 = 0xF0D0;

/// The phrase every refusal of an unapproved leaf carries, whether the gate
/// refused it inside mls-rs or the session refused it afterwards. mls-rs turns
/// an IdentityProvider error into a string of its own, so this text is the one
/// thing both paths are guaranteed to share, and the C ABI edge keys a
/// distinct status code on it.
pub const NOT_APPROVED: &str = "not approved by the leaf declaration check";

#[derive(Clone, Default)]
enum Mode {
    /// Admit everything. Only the collect pass runs in this mode.
    Collect,
    /// Admit this device, and whatever was approved for this operation.
    #[default]
    Enforce,
}

#[derive(Default)]
struct State {
    mode: Mode,
    admitted: Vec<SigningIdentity>,
}

/// The identity provider every session is built with. Clones share one state,
/// which is how the session changes what the client it built will accept.
#[derive(Clone)]
pub struct LeafGate {
    this_device: SigningIdentity,
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
pub enum GateError {
    NotBasic,
    NotApproved,
    Poisoned,
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            GateError::NotBasic => "leaf credential is not a basic credential",
            GateError::NotApproved => {
                return write!(f, "leaf was {NOT_APPROVED}");
            }
            GateError::Poisoned => "leaf gate state is poisoned",
        })
    }
}

impl std::error::Error for GateError {}

impl IntoAnyError for GateError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

impl LeafGate {
    pub fn new(this_device: SigningIdentity) -> Self {
        Self {
            this_device,
            state: Arc::default(),
        }
    }

    /// Admit everything until the next `enforce`.
    pub fn collect(&self) -> Result<(), String> {
        self.set(Mode::Collect, Vec::new())
    }

    /// Admit exactly this device and `admitted`.
    pub fn enforce(&self, admitted: Vec<SigningIdentity>) -> Result<(), String> {
        self.set(Mode::Enforce, admitted)
    }

    fn set(&self, mode: Mode, admitted: Vec<SigningIdentity>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "mls: leaf gate state is poisoned".to_string())?;
        state.mode = mode;
        state.admitted = admitted;
        Ok(())
    }

    fn admits(&self, identity: &SigningIdentity) -> Result<(), GateError> {
        let state = self.state.lock().map_err(|_| GateError::Poisoned)?;
        match state.mode {
            Mode::Collect => Ok(()),
            Mode::Enforce if *identity == self.this_device => Ok(()),
            Mode::Enforce if state.admitted.contains(identity) => Ok(()),
            Mode::Enforce => Err(GateError::NotApproved),
        }
    }
}

fn basic(identity: &SigningIdentity) -> Result<&BasicCredential, GateError> {
    identity.credential.as_basic().ok_or(GateError::NotBasic)
}

impl IdentityProvider for LeafGate {
    type Error = GateError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        basic(signing_identity)?;
        self.admits(signing_identity)
    }

    // No group this device creates has external senders, and one that claims
    // to has not been through any check here.
    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Err(GateError::NotApproved)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(basic(signing_identity)?.identifier.to_vec())
    }

    // A member's leaf may never change the identity it claims. It may change
    // the key it signs with only to a successor this operation admitted: a
    // leaf rotation reaches existing groups as an Update carrying the new key
    // (design P3), and the declaration that vouched for the old key says
    // nothing about the new one, so the new leaf goes through the same
    // approval list an Add does. In `Collect` everything is admitted, which is
    // what lets the collect pass report the replacement for Go to verify.
    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let before = basic(predecessor)?;
        let after = basic(successor)?;
        if before.identifier != after.identifier {
            return Ok(false);
        }
        if predecessor == successor {
            return Ok(true);
        }
        match self.admits(successor) {
            Ok(()) => Ok(true),
            Err(GateError::NotApproved) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![BasicCredential::credential_type()]
    }
}

// ─── the framing the Go side reads and writes ──────────────────────────────

/// One leaf as the collect pass saw it. `declaration` is the raw payload of
/// the leaf declaration extension, or `None` when the leaf carries none: the
/// Go side must be able to tell "no extension" from "an empty one".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub index: u32,
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub declaration: Option<Vec<u8>>,
}

impl Leaf {
    pub fn from_parts(index: u32, identity: &SigningIdentity, extensions: &ExtensionList) -> Self {
        Self {
            index,
            // A non-basic credential has no identity bytes to show, and an
            // empty identity is one the Go side refuses.
            identity: identity
                .credential
                .as_basic()
                .map(|b| b.identifier.to_vec())
                .unwrap_or_default(),
            signature_key: identity.signature_key.as_bytes().to_vec(),
            declaration: extensions
                .get(LEAF_DECLARATION_EXTENSION.into())
                .map(|e| e.extension_data),
        }
    }
}

/// Ceiling on how many leaves one message may bring in, so a hostile count
/// cannot size an allocation. RFC 9420 puts no bound on group size; this is
/// ours, and far above any group a person would be asked to approve.
pub const MAX_LEAVES: usize = 4096;

/// Leaves are framed as `u32 count` then, per leaf, `u32 index`, a
/// length-prefixed identity, a length-prefixed signature key, and a
/// presence byte followed by a length-prefixed declaration when it is 1. All
/// integers are big-endian.
pub fn encode_leaves(leaves: &[Leaf]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, len_u32(leaves.len()));
    for leaf in leaves {
        put_u32(&mut out, leaf.index);
        put_bytes(&mut out, &leaf.identity);
        put_bytes(&mut out, &leaf.signature_key);
        match &leaf.declaration {
            Some(d) => {
                out.push(1);
                put_bytes(&mut out, d);
            }
            None => out.push(0),
        }
    }
    out
}

/// A leaf the Go side verified: the credential identity and signature key the
/// gate admits, and the declaration bytes it checked, which the session
/// compares against what the operation actually brought in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub declaration: Vec<u8>,
}

impl Approval {
    /// Whether `leaf` is the leaf this approval was given for. The index is
    /// not part of it: an approval names a leaf, not a slot in the tree.
    pub fn covers(&self, leaf: &Leaf) -> bool {
        self.identity == leaf.identity
            && self.signature_key == leaf.signature_key
            && leaf.declaration.as_deref() == Some(self.declaration.as_slice())
    }
}

/// Approvals are framed as `u32 count` then, per entry, a length-prefixed
/// identity, signature key and declaration. The identity and key are compared
/// byte for byte with the leaf's, which is the same as comparing
/// `(account_id, device_id, signature key fingerprint)`: the identity has
/// exactly one spelling per `(account_id, device_id)` and the fingerprint is a
/// hash of exactly these key bytes.
pub fn decode_approvals(buf: &[u8]) -> Result<Vec<Approval>, &'static str> {
    let mut cur = Reader { buf, at: 0 };
    let count = usize::try_from(cur.u32()?).map_err(|_| "approval count does not fit")?;
    if count > MAX_LEAVES {
        return Err("too many approved leaves");
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(Approval {
            identity: cur.prefixed()?.to_vec(),
            signature_key: cur.prefixed()?.to_vec(),
            declaration: cur.prefixed()?.to_vec(),
        });
    }
    if cur.at != buf.len() {
        return Err("approval list has trailing bytes");
    }
    Ok(out)
}

/// KeyPackages for one Commit are framed as `u32 count` then a u32-length-
/// prefixed MLSMessage each, big-endian.
pub fn decode_key_packages(buf: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let mut cur = Reader { buf, at: 0 };
    let count = usize::try_from(cur.u32()?).map_err(|_| "key package count does not fit")?;
    if count == 0 || count > MAX_LEAVES {
        return Err("key package count is out of range");
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(cur.prefixed()?);
    }
    if cur.at != buf.len() {
        return Err("key package list has trailing bytes");
    }
    Ok(out)
}

/// Leaf indices for one Remove Commit are framed as `u32 count` then one
/// big-endian u32 each.
pub fn decode_leaf_indices(buf: &[u8]) -> Result<Vec<u32>, &'static str> {
    let mut cur = Reader { buf, at: 0 };
    let count = usize::try_from(cur.u32()?).map_err(|_| "leaf index count does not fit")?;
    if count == 0 || count > MAX_LEAVES {
        return Err("leaf index count is out of range");
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(cur.u32()?);
    }
    if cur.at != buf.len() {
        return Err("leaf index list has trailing bytes");
    }
    Ok(out)
}

/// Report the leaves in `after` that `before` does not hold identically at the
/// same index. A leaf whose declaration changed through an update path counts
/// as new: the declaration is what the Go side vouched for, not the index.
pub fn new_leaves(before: &[Leaf], after: &[Leaf]) -> Vec<Leaf> {
    after
        .iter()
        .filter(|leaf| !before.iter().any(|old| old == *leaf))
        .cloned()
        .collect()
}

fn len_u32(n: usize) -> u32 {
    // Every length framed here is bounded well below u32::MAX (MAX_LEAVES and
    // the codec's own vector limits), so saturating can only ever mask a bug
    // that the Go decoder then catches as a length mismatch.
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, len_u32(b.len()));
    out.extend_from_slice(b);
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self.at.checked_add(n).ok_or("approval list is truncated")?;
        let out = self
            .buf
            .get(self.at..end)
            .ok_or("approval list is truncated")?;
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let b = self.take(4)?;
        let arr: [u8; 4] = b.try_into().map_err(|_| "approval list is truncated")?;
        Ok(u32::from_be_bytes(arr))
    }

    fn prefixed(&mut self) -> Result<&'a [u8], &'static str> {
        let n = usize::try_from(self.u32()?).map_err(|_| "approval length does not fit")?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(id: &[u8], key: &[u8]) -> SigningIdentity {
        SigningIdentity::new(
            BasicCredential::new(id.to_vec()).into_credential(),
            key.to_vec().into(),
        )
    }

    #[test]
    fn leaf_indices_are_decoded_strictly() {
        let mut framed = 2u32.to_be_bytes().to_vec();
        framed.extend_from_slice(&7u32.to_be_bytes());
        framed.extend_from_slice(&9u32.to_be_bytes());
        assert_eq!(decode_leaf_indices(&framed), Ok(vec![7, 9]));

        assert!(decode_leaf_indices(&0u32.to_be_bytes()).is_err());
        assert!(decode_leaf_indices(&framed[..framed.len() - 1]).is_err());
        let mut trailing = framed.clone();
        trailing.push(0);
        assert!(decode_leaf_indices(&trailing).is_err());
    }

    #[test]
    fn enforce_admits_only_this_device_and_the_approved() {
        let me = identity(b"me", b"k-me");
        let gate = LeafGate::new(me.clone());
        let other = identity(b"other", b"k-other");

        assert!(gate.admits(&me).is_ok());
        assert!(gate.admits(&other).is_err());

        gate.enforce(vec![other.clone()]).unwrap();
        assert!(gate.admits(&other).is_ok());
        // Same identity, different key: a different leaf.
        assert!(gate.admits(&identity(b"other", b"k-swapped")).is_err());

        gate.collect().unwrap();
        assert!(gate.admits(&identity(b"anyone", b"k")).is_ok());
    }

    // The identity never changes. The key changes only to a successor the
    // operation admitted, which is how a rotated leaf enters (design P3).
    #[test]
    fn a_successor_keeps_its_identity_and_changes_its_key_only_when_admitted() {
        let gate = LeafGate::new(identity(b"me", b"k"));
        let a = identity(b"a", b"k1");
        let rotated = identity(b"a", b"k2");
        let none = ExtensionList::new();
        assert!(gate.valid_successor(&a, &a, &none).unwrap());
        assert!(!gate.valid_successor(&a, &rotated, &none).unwrap());
        assert!(!gate
            .valid_successor(&a, &identity(b"b", b"k1"), &none)
            .unwrap());

        gate.enforce(vec![rotated.clone()]).unwrap();
        assert!(gate.valid_successor(&a, &rotated, &none).unwrap());
        assert!(!gate
            .valid_successor(&a, &identity(b"b", b"k2"), &none)
            .unwrap());

        gate.collect().unwrap();
        assert!(gate.valid_successor(&a, &rotated, &none).unwrap());
        assert!(!gate
            .valid_successor(&a, &identity(b"b", b"k1"), &none)
            .unwrap());
    }

    #[test]
    fn approvals_round_trip_and_refuse_malformed_input() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 1);
        put_bytes(&mut buf, b"id");
        put_bytes(&mut buf, b"key");
        put_bytes(&mut buf, b"decl");
        let want = Approval {
            identity: b"id".to_vec(),
            signature_key: b"key".to_vec(),
            declaration: b"decl".to_vec(),
        };
        assert_eq!(decode_approvals(&buf).unwrap(), vec![want.clone()]);

        assert!(decode_approvals(&buf[..buf.len() - 1]).is_err());
        let mut longer = buf.clone();
        longer.push(0);
        assert!(decode_approvals(&longer).is_err());

        let mut huge = Vec::new();
        put_u32(&mut huge, u32::MAX);
        assert!(decode_approvals(&huge).is_err());

        let leaf = Leaf {
            index: 7,
            identity: b"id".to_vec(),
            signature_key: b"key".to_vec(),
            declaration: Some(b"decl".to_vec()),
        };
        assert!(want.covers(&leaf));
        assert!(!want.covers(&Leaf {
            declaration: Some(b"other".to_vec()),
            ..leaf.clone()
        }));
        assert!(!want.covers(&Leaf {
            declaration: None,
            ..leaf
        }));
    }

    #[test]
    fn a_changed_declaration_at_the_same_index_is_a_new_leaf() {
        let leaf = Leaf {
            index: 1,
            identity: b"a".to_vec(),
            signature_key: b"k".to_vec(),
            declaration: Some(b"d1".to_vec()),
        };
        let edited = Leaf {
            declaration: Some(b"d2".to_vec()),
            ..leaf.clone()
        };
        assert!(new_leaves(std::slice::from_ref(&leaf), std::slice::from_ref(&leaf)).is_empty());
        assert_eq!(
            new_leaves(std::slice::from_ref(&leaf), std::slice::from_ref(&edited)),
            vec![edited]
        );
    }
}
