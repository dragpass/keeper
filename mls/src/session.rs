// session.rs — one conversation's MLS client and group, and the policy this
// integration fixes rather than inherits.

use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::error::MlsError;
use mls_rs::extension::built_in::RequiredCapabilitiesExt;
use mls_rs::group::proposal::{AddProposal, Proposal};
use mls_rs::group::{CommitEffect, ReceivedMessage};
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::EncryptionOptions;
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, Group,
    MlsMessage,
};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use zeroize::Zeroizing;

use crate::authority::{AuthorityRules, CommitShape, RemovalApproval};
use crate::gate::{self, Approval, Leaf, LeafGate, LEAF_DECLARATION_EXTENSION};
use crate::storage::{KeyPackageCustody, RecordStorage};

/// RFC 9420 ciphersuite 1. The rustcrypto provider implements 1, 2, 3 and 7;
/// 4, 5 and 6 are absent because the curves behind them are not implemented
/// there. Pinned to one value here because a skeleton that negotiates has an
/// untested branch, not because the others are ruled out.
pub const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// The longest a KeyPackage this device produces stays valid. mls-rs defaults
/// to a year; ariadne accepts a declared `not_after` of at most 90 days ahead,
/// and the declared value has to be the real one, so the real one is kept a day
/// inside that ceiling for clock skew and upload delay. A KeyPackage never
/// outlives the leaf declaration it embeds either, so the caller's cap usually
/// ends it sooner (`key_package`).
pub const KEY_PACKAGE_LIFETIME: std::time::Duration =
    std::time::Duration::from_secs(89 * 24 * 60 * 60);

type Config = WithKeyPackageRepo<
    KeyPackageCustody,
    WithMlsRules<
        AuthorityRules,
        WithGroupStateStorage<
            RecordStorage,
            WithIdentityProvider<LeafGate, WithCryptoProvider<RustCryptoProvider, BaseConfig>>,
        >,
    >,
>;

/// One KeyPackage as generation hands it out: the public message, its
/// KeyPackage reference, and the private entry the caller must persist before
/// anyone can be given the message.
pub struct GeneratedKeyPackage {
    pub message: Vec<u8>,
    pub reference: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
}

pub struct Session {
    client: Client<Config>,
    storage: RecordStorage,
    custody: KeyPackageCustody,
    gate: LeafGate,
    rules: AuthorityRules,
    /// The leaf this session was opened as: the device's active key, which a
    /// group loaded from an older snapshot may not be signing with yet. An
    /// Update is how a group moves onto it (`build_update`). The client holds
    /// the same key but does not hand it back, hence the copy;
    /// `SignatureSecretKey` zeroizes on drop.
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    /// This device's own leaf declaration, carried in every leaf it creates:
    /// its KeyPackages, the first leaf of a group it creates, and the leaf an
    /// Update replaces its old one with. Empty only for the throwaway members
    /// tests build.
    leaf_extensions: ExtensionList,
    /// What the Go side approved for the next group operation, and only that
    /// one. Every operation that can bring a leaf in takes it.
    approved: Vec<Approval>,
    /// The Removes the Go side approved for the next group operation, and only
    /// that one: the authority half of `approved` (authority.rs).
    approved_removals: Vec<RemovalApproval>,
    group: Option<Group<Config>>,
}

/// The wire form a message went out in. Read back off the encoded bytes rather
/// than off the setting that produced them, so that a change in an upstream
/// default shows up as a changed answer here.
#[repr(u8)]
pub enum WireForm {
    Public = 1,
    Private = 2,
    Welcome = 3,
    KeyPackage = 4,
    GroupInfo = 5,
    Other = 0,
}

/// Every fallible call here answers with a message rather than an error type.
/// The C ABI can only carry a status code and a string, so converting once at
/// this edge keeps the conversion out of every entry point.
pub type Res<T> = Result<T, String>;

fn err(context: &str, e: impl core::fmt::Display) -> String {
    format!("mls: {context}: {e}")
}

/// Marks the refusal of a message this session's own leaf sent. mls-rs
/// refuses it after opening the sender data and before deriving any content
/// key, so nothing is consumed; the C ABI edge turns the marker into its own
/// status code because Go treats it as "read this from local history", not as
/// a failure.
pub const FROM_SELF: &str = "the message was sent by this leaf";

pub struct Processed {
    pub epoch: u64,
    pub removed: bool,
    pub application: Option<Zeroizing<Vec<u8>>>,
    /// SenderData.leaf_index, which the wire format keeps encrypted. Together
    /// with the epoch, the axis and the generation it is the four-slot name of
    /// one inbound position; two of the four are only knowable after the
    /// decrypt, which is why this travels back with the plaintext.
    pub sender_index: u32,
    pub authenticated_data: Vec<u8>,
    /// The generation the library actually derived the keys from.
    ///
    /// `None` is carried as `None` and never as a number. Upstream turns an
    /// extraction failure into `None` by way of `unwrap_or_default` on the
    /// error, so a caller that substitutes zero here cannot tell "checked it"
    /// from "could not look".
    pub key_generation: Option<u32>,
}

pub fn generate_signature_key() -> Res<(Vec<u8>, Vec<u8>)> {
    let provider = RustCryptoProvider::default()
        .cipher_suite_provider(CIPHER_SUITE)
        .ok_or_else(|| "mls: crypto provider has no ciphersuite 1".to_string())?;
    let (secret, public) = provider
        .signature_key_generate()
        .map_err(|e| err("signature key generate", e))?;
    Ok((secret.as_bytes().to_vec(), public.as_bytes().to_vec()))
}

fn signing_identity(identity: &[u8], signature_key: &[u8]) -> SigningIdentity {
    SigningIdentity::new(
        BasicCredential::new(identity.to_vec()).into_credential(),
        signature_key.to_vec().into(),
    )
}

fn leaves_of(group: &Group<Config>) -> Vec<Leaf> {
    group
        .roster()
        .members_iter()
        .map(|m| Leaf::from_parts(m.index, &m.signing_identity, &m.extensions))
        .collect()
}

/// Refuse the operation unless every leaf it brought in is one the Go side
/// approved, declaration bytes included. The gate already refused any
/// credential and key nobody approved; this is the half of the check the gate
/// cannot make, because mls-rs shows an IdentityProvider the signing identity
/// and not the leaf's extensions.
fn require_approved(new: &[Leaf], approved: &[Approval]) -> Res<()> {
    if new
        .iter()
        .all(|leaf| approved.iter().any(|a| a.covers(leaf)))
    {
        Ok(())
    } else {
        Err(format!(
            "mls: a leaf entering the group was {}",
            gate::NOT_APPROVED
        ))
    }
}

/// Read the leaf a KeyPackage would add, without a group and without applying
/// anything. The index is meaningless here and is 0.
pub fn key_package_leaf(key_package: &[u8]) -> Res<Leaf> {
    let msg = MlsMessage::from_bytes(key_package).map_err(|e| err("key package decode", e))?;
    let add = AddProposal::try_from(msg).map_err(|e| err("key package decode", e))?;
    Ok(Leaf::from_parts(
        0,
        add.signing_identity(),
        &add.leaf_node_extensions(),
    ))
}

/// The leaves a Commit that removed this device adds for everyone else.
///
/// A removed member's group does not move to the new epoch, so its roster after
/// the Commit is the roster before it and the diff in `process_collect` would
/// see nobody new. mls-rs still validates every added member against the gate
/// before it reports the removal, so without these the enforce pass refuses the
/// Commit that removes this device whenever it also adds someone — which is
/// exactly what a replace Commit (design M4.4) does to the old device.
///
/// Only Adds are listed. This integration never sends a by-reference Update,
/// and a leaf one of them (or the committer's path) would change is left out,
/// so the gate refuses such a Commit here: the fail-closed direction.
fn added_to_a_group_left_behind(received: &ReceivedMessage) -> Vec<Leaf> {
    let ReceivedMessage::Commit(commit) = received else {
        return Vec::new();
    };
    let CommitEffect::Removed { new_epoch, .. } = &commit.effect else {
        return Vec::new();
    };
    new_epoch
        .applied_proposals
        .iter()
        .filter_map(|info| match &info.proposal {
            Proposal::Add(add) => Some(Leaf::from_parts(
                0,
                add.signing_identity(),
                &add.leaf_node_extensions(),
            )),
            _ => None,
        })
        .collect()
}

/// The KeyPackage references a Welcome is addressed to: one per new member it
/// carries secrets for. Empty for anything that is not a Welcome.
pub fn welcome_key_package_refs(welcome: &[u8]) -> Res<Vec<Vec<u8>>> {
    let msg = MlsMessage::from_bytes(welcome).map_err(|e| err("welcome decode", e))?;
    Ok(msg
        .welcome_key_package_references()
        .into_iter()
        .map(|r| r.to_vec())
        .collect())
}

/// The `not_after` of a KeyPackage's lifetime, in Unix seconds: what the
/// client declares to the server when it uploads the KeyPackage.
pub fn key_package_not_after(key_package: &[u8]) -> Res<u64> {
    let kp = MlsMessage::from_bytes(key_package)
        .map_err(|e| err("key package decode", e))?
        .into_key_package()
        .ok_or_else(|| "mls: message is not a key package".to_string())?;
    Ok(kp
        .expiration()
        .map_err(|e| err("key package lifetime", e))?
        .seconds_since_epoch())
}

impl Session {
    pub fn new(
        identity: &[u8],
        secret_key: &[u8],
        public_key: &[u8],
        declaration: &[u8],
    ) -> Res<Self> {
        let storage = RecordStorage::new();
        let custody = KeyPackageCustody::new();
        let signing_identity = signing_identity(identity, public_key);
        let gate = LeafGate::new(signing_identity.clone());

        let mut leaf_extensions = ExtensionList::new();
        if !declaration.is_empty() {
            leaf_extensions.set(Extension::new(
                LEAF_DECLARATION_EXTENSION.into(),
                declaration.to_vec(),
            ));
        }

        // encrypt_control_messages is set here rather than left to Default.
        // EncryptionOptions derives Default, so false is already what we would
        // get; writing it down is what makes the choice reviewable and what
        // makes a later upstream flip of that default a compile-time-visible
        // change in this file instead of a silent change in behaviour.
        //
        // What false buys and costs is decided elsewhere (design §7.3.4): the
        // Commit goes out as a PublicMessage, so its FramedContent — sender
        // leaf index, epoch, proposal shapes — is metadata the server can read,
        // and in exchange the handshake ratchet is never consumed, which leaves
        // the send-ordering discipline with a single axis to defend.
        let rules = AuthorityRules::new(EncryptionOptions::new(false, PaddingMode::StepFunction));

        // The capability is advertised by every leaf this client makes, which
        // is what RFC 9420 §7.2 requires of a leaf that carries the extension
        // and what lets a group list it in required_capabilities.
        let client = Client::builder()
            .extension_type(LEAF_DECLARATION_EXTENSION.into())
            .key_package_lifetime(KEY_PACKAGE_LIFETIME)
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(gate.clone())
            .group_state_storage(storage.clone())
            .mls_rules(rules.clone())
            .key_package_repo(custody.clone())
            .signing_identity(
                signing_identity.clone(),
                secret_key.to_vec().into(),
                CIPHER_SUITE,
            )
            .build();

        Ok(Self {
            client,
            storage,
            custody,
            gate,
            rules,
            signing_identity,
            signer: secret_key.to_vec().into(),
            leaf_extensions,
            approved: Vec::new(),
            approved_removals: Vec::new(),
            group: None,
        })
    }

    /// One single-use KeyPackage carrying this device's declaration, ending no
    /// later than `not_after_cap` (Unix seconds) — the declaration's own
    /// `not_after`, which a KeyPackage embedding it must not outlive. There is
    /// no last-resort KeyPackage: every one produced here is meant to be
    /// consumed once.
    ///
    /// The private keys come back in the result and nothing of them stays in
    /// this session. Until the caller has persisted them, the message must not
    /// be handed to anyone: a Welcome to it could never be joined.
    pub fn key_package(&self, not_after_cap: u64) -> Res<GeneratedKeyPackage> {
        let now = MlsTime::now().seconds_since_epoch();
        let remaining = not_after_cap
            .checked_sub(now)
            .filter(|s| *s > 0)
            .ok_or_else(|| "mls: the leaf declaration has already expired".to_string())?;
        let lifetime =
            std::time::Duration::from_secs(remaining.min(KEY_PACKAGE_LIFETIME.as_secs()));
        // A client per call because the lifetime is a client setting. It shares
        // this session's custody, so the entry lands where `take` finds it.
        // `now` is passed as the timestamp so not_before and the cap arithmetic
        // read the same second.
        let client = self
            .client
            .to_builder(None)
            .key_package_lifetime(lifetime)
            .build();
        self.custody.clear();
        let generated = client
            .generate_key_package_message(
                Default::default(),
                self.leaf_extensions.clone(),
                Some(MlsTime::from(now)),
            )
            .map_err(|e| err("key package", e));
        let (reference, private) = self.custody.take().map_err(str::to_string)?;
        let message = generated?
            .to_bytes()
            .map_err(|e| err("key package encode", e))?;
        Ok(GeneratedKeyPackage {
            message,
            reference,
            private,
        })
    }

    /// Hand this session the private entry of the KeyPackage a Welcome is
    /// addressed to, for the next join only. `join` drops it again whether
    /// the join succeeds or not.
    pub fn install_key_package(&self, entry: &[u8]) -> Res<()> {
        self.custody.install(entry).map_err(str::to_string)?;
        Ok(())
    }

    /// Create a group that only members advertising the leaf declaration
    /// extension can join. mls-rs checks required_capabilities against every
    /// leaf it adds, so a KeyPackage from a client that does not know the
    /// extension is refused before any Go check runs (fail closed).
    pub fn create_group(&mut self, group_id: &[u8]) -> Res<()> {
        let mut context_extensions = ExtensionList::new();
        context_extensions
            .set_from(RequiredCapabilitiesExt {
                extensions: vec![LEAF_DECLARATION_EXTENSION.into()],
                proposals: Vec::new(),
                credentials: Vec::new(),
            })
            .map_err(|e| err("required capabilities", e))?;
        self.gate.enforce(Vec::new())?;
        self.group = Some(
            self.client
                .create_group_with_id(
                    group_id.to_vec(),
                    context_extensions,
                    self.leaf_extensions.clone(),
                    None,
                )
                .map_err(|e| err("create group", e))?,
        );
        Ok(())
    }

    /// Set what the Go side approved for the next group operation. Replaces
    /// any earlier approval that no operation consumed.
    pub fn approve(&mut self, approved: Vec<Approval>) {
        self.approved = approved;
    }

    /// Set the Removes the Go side approved for the next group operation.
    /// Replaces any earlier approval that no operation consumed.
    pub fn approve_removals(&mut self, removals: Vec<RemovalApproval>) {
        self.approved_removals = removals;
    }

    /// Open the gate to the current members plus this operation's approvals,
    /// and hand the approvals back for the post-check. Taking them here is what
    /// makes an approval single-use.
    fn arm(&mut self) -> Res<Vec<Approval>> {
        let approved = std::mem::take(&mut self.approved);
        let mut admitted: Vec<SigningIdentity> = match &self.group {
            Some(g) => g
                .roster()
                .members_iter()
                .map(|m| m.signing_identity)
                .collect(),
            None => Vec::new(),
        };
        admitted.extend(
            approved
                .iter()
                .map(|a| signing_identity(&a.identity, &a.signature_key)),
        );
        self.gate.enforce(admitted)?;
        self.rules
            .enforce(std::mem::take(&mut self.approved_removals))?;
        Ok(approved)
    }

    fn disarm(&self) -> Res<()> {
        self.gate.enforce(Vec::new())?;
        self.rules.enforce(Vec::new())
    }

    /// The collect pass of a join: process the Welcome with every leaf
    /// admitted, report the whole tree, and keep nothing. The group it built
    /// is dropped here, and mls-rs only deletes the consumed KeyPackage when a
    /// group is written to storage, so the enforce pass can use it again.
    pub fn join_collect(&mut self, welcome: &[u8]) -> Res<Vec<Leaf>> {
        let msg = MlsMessage::from_bytes(welcome).map_err(|e| err("welcome decode", e))?;
        self.gate.collect()?;
        let joined = self.client.join_group(None, &msg, None);
        self.disarm()?;
        let (group, _) = joined.map_err(|e| err("join group", e))?;
        Ok(leaves_of(&group))
    }

    /// Join from a Welcome. Every leaf of the tree, the committer's and this
    /// device's included, must have been approved: a joiner has no earlier
    /// state that vouched for anyone.
    pub fn join(&mut self, welcome: &[u8]) -> Res<()> {
        let joined = self.join_once(welcome);
        self.custody.clear();
        joined
    }

    fn join_once(&mut self, welcome: &[u8]) -> Res<()> {
        let msg = MlsMessage::from_bytes(welcome).map_err(|e| err("welcome decode", e))?;
        let approved = std::mem::take(&mut self.approved);
        self.approved_removals.clear();
        self.gate.enforce(
            approved
                .iter()
                .map(|a| signing_identity(&a.identity, &a.signature_key))
                .collect(),
        )?;
        let joined = self.client.join_group(None, &msg, None);
        self.disarm()?;
        let (group, _) = joined.map_err(|e| err("join group", e))?;
        require_approved(&leaves_of(&group), &approved)?;
        self.group = Some(group);
        Ok(())
    }

    /// Restore from the blob Keeper stored. The group id travels inside the
    /// blob because `GroupStateStorage` keys on it and `load_group` asks for it
    /// by name.
    pub fn load(&mut self, blob: &[u8]) -> Res<()> {
        let group_id = self.storage.decode_into(blob).map_err(str::to_string)?;
        self.group = Some(
            self.client
                .load_group(&group_id)
                .map_err(|e| err("load group", e))?,
        );
        Ok(())
    }

    #[cfg(test)]
    fn roster_len(&self) -> usize {
        self.group
            .as_ref()
            .map_or(0, |g| g.roster().members_iter().count())
    }

    fn group_mut(&mut self) -> Res<&mut Group<Config>> {
        self.group
            .as_mut()
            .ok_or_else(|| "mls: session has no group".to_string())
    }

    /// Build a Commit that adds these members, **without applying it**.
    ///
    /// RFC 9420 §14: "The generation of Commit messages MUST NOT modify a
    /// client's state, since the client doesn't know at that time whether the
    /// changes implied by the Commit message will conflict with another Commit
    /// or not." `build()` honours that — it puts the next epoch's state,
    /// secrets and key schedule in `Group::pending_commit` and assigns none of
    /// them to the group. The assignment happens only in
    /// `apply_detached_commit`, which `apply_pending_commit` calls.
    ///
    /// The epoch returned is the **confirmed** one, the epoch this Commit was
    /// built against. It is what the server compares under its CAS, and it is
    /// deliberately not the epoch the Commit would produce: nothing here knows
    /// yet whether that epoch will exist.
    ///
    /// Every member being added must have been approved for this call, and
    /// the gate is what mls-rs consults while it validates each KeyPackage.
    /// One unapproved member refuses the whole Commit.
    pub fn commit_add_members(&mut self, key_packages: &[&[u8]]) -> Res<(Vec<u8>, Vec<u8>, u64)> {
        let mut leaves = Vec::with_capacity(key_packages.len());
        let mut messages = Vec::with_capacity(key_packages.len());
        for kp in key_packages {
            leaves.push(key_package_leaf(kp)?);
            messages.push(MlsMessage::from_bytes(kp).map_err(|e| err("key package decode", e))?);
        }
        self.group_mut()?;
        let approved = self.arm()?;
        // Checked before the build, so a refusal leaves no pending Commit.
        let built = require_approved(&leaves, &approved).and_then(|()| self.build_add(messages));
        self.disarm()?;
        let (output, expected_epoch) = built?;
        let welcome = match output.welcome_messages.first() {
            Some(w) => w.to_bytes().map_err(|e| err("welcome encode", e))?,
            None => Vec::new(),
        };
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| err("commit encode", e))?;
        Ok((commit, welcome, expected_epoch))
    }

    fn build_add(
        &mut self,
        key_packages: Vec<MlsMessage>,
    ) -> Res<(mls_rs::group::CommitOutput, u64)> {
        let group = self.group_mut()?;
        let expected_epoch = group.current_epoch();
        let mut builder = group.commit_builder();
        for kp in key_packages {
            builder = builder.add_member(kp).map_err(|e| err("add member", e))?;
        }
        let output = builder.build().map_err(|e| err("commit build", e))?;
        Ok((output, expected_epoch))
    }

    /// Build a Commit with no proposals — the path update that rotates this
    /// device's own key material. Same pending discipline as
    /// `commit_add_member`.
    ///
    /// When the group still signs as an older leaf key than the one this
    /// session was opened with, the Update replaces the leaf with the active
    /// key and its declaration. That is how a leaf rotation reaches groups
    /// that already hold the device: nothing else carries the new key into
    /// them. Receivers see the replacement as an entering leaf and verify it
    /// in full before their gate admits it (`LeafGate::valid_successor`).
    pub fn commit_update(&mut self) -> Res<(Vec<u8>, u64)> {
        self.group_mut()?;
        self.arm()?;
        let built = self.build_update();
        self.disarm()?;
        let (output, expected_epoch) = built?;
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| err("commit encode", e))?;
        Ok((commit, expected_epoch))
    }

    fn build_update(&mut self) -> Res<(mls_rs::group::CommitOutput, u64)> {
        let active = self.signing_identity.clone();
        let signer = self.signer.clone();
        let extensions = self.leaf_extensions.clone();
        let group = self.group_mut()?;
        let expected_epoch = group.current_epoch();
        let current = group
            .current_member_signing_identity()
            .map_err(|e| err("own leaf", e))?
            .clone();
        let mut builder = group.commit_builder();
        if current != active {
            builder = builder
                .set_new_signing_identity(signer, active)
                .set_leaf_node_extensions(extensions);
        }
        let output = builder.build().map_err(|e| err("commit build", e))?;
        Ok((output, expected_epoch))
    }

    /// Build a Commit that removes these leaves, **without applying it**. Same
    /// pending discipline as `commit_add_members`: the leaves stay in the
    /// confirmed tree, and so in `roster`, until `apply_pending_commit`.
    pub fn commit_remove_members(&mut self, leaf_indices: &[u32]) -> Res<(Vec<u8>, u64)> {
        if leaf_indices.is_empty() {
            return Err("mls: a remove commit needs at least one leaf".to_string());
        }
        self.group_mut()?;
        self.arm()?;
        let built = self.build_remove(leaf_indices);
        self.disarm()?;
        let (output, expected_epoch) = built?;
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| err("commit encode", e))?;
        Ok((commit, expected_epoch))
    }

    fn build_remove(&mut self, leaf_indices: &[u32]) -> Res<(mls_rs::group::CommitOutput, u64)> {
        let group = self.group_mut()?;
        let expected_epoch = group.current_epoch();
        let mut builder = group.commit_builder();
        for &index in leaf_indices {
            builder = builder
                .remove_member(index)
                .map_err(|e| err("remove member", e))?;
        }
        let output = builder.build().map_err(|e| err("commit build", e))?;
        Ok((output, expected_epoch))
    }

    /// Build one Commit that removes `leaf_indices` and adds `key_packages`,
    /// **without applying it**: how the remaining members replace an account's
    /// old leaf with the leaf of the device that took it over (design M4.4).
    /// One Commit rather than a Remove then an Add, because between the two
    /// there would be an epoch that holds neither leaf or both.
    ///
    /// Same pending discipline and the same gate as `commit_add_members`:
    /// every added leaf must have been approved for this call, and a refusal
    /// is decided before the build, so it leaves no pending Commit.
    pub fn commit_replace_members(
        &mut self,
        leaf_indices: &[u32],
        key_packages: &[&[u8]],
    ) -> Res<(Vec<u8>, Vec<u8>, u64)> {
        if leaf_indices.is_empty() || key_packages.is_empty() {
            return Err("mls: a replace commit needs a leaf to remove and one to add".to_string());
        }
        let mut leaves = Vec::with_capacity(key_packages.len());
        let mut messages = Vec::with_capacity(key_packages.len());
        for kp in key_packages {
            leaves.push(key_package_leaf(kp)?);
            messages.push(MlsMessage::from_bytes(kp).map_err(|e| err("key package decode", e))?);
        }
        self.group_mut()?;
        let approved = self.arm()?;
        let built = require_approved(&leaves, &approved)
            .and_then(|()| self.build_replace(leaf_indices, messages));
        self.disarm()?;
        let (output, expected_epoch) = built?;
        let welcome = match output.welcome_messages.first() {
            Some(w) => w.to_bytes().map_err(|e| err("welcome encode", e))?,
            None => Vec::new(),
        };
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| err("commit encode", e))?;
        Ok((commit, welcome, expected_epoch))
    }

    fn build_replace(
        &mut self,
        leaf_indices: &[u32],
        key_packages: Vec<MlsMessage>,
    ) -> Res<(mls_rs::group::CommitOutput, u64)> {
        let group = self.group_mut()?;
        let expected_epoch = group.current_epoch();
        let mut builder = group.commit_builder();
        for &index in leaf_indices {
            builder = builder
                .remove_member(index)
                .map_err(|e| err("remove member", e))?;
        }
        for kp in key_packages {
            builder = builder.add_member(kp).map_err(|e| err("add member", e))?;
        }
        let output = builder.build().map_err(|e| err("commit build", e))?;
        Ok((output, expected_epoch))
    }

    /// Every leaf of the confirmed tree. `Group::roster` reads the group's own
    /// state and a built Commit lives in `pending_commit` beside it, so a
    /// Remove this device has built but the server has not accepted leaves
    /// the removed leaf here. S-1's unlatch depends on exactly that.
    pub fn roster(&mut self) -> Res<Vec<Leaf>> {
        Ok(leaves_of(self.group_mut()?))
    }

    pub fn group_id(&mut self) -> Res<Vec<u8>> {
        Ok(self.group_mut()?.group_id().to_vec())
    }

    /// Promote the pending Commit to confirmed. Called only once the server's
    /// CAS has said this Commit is the one that won its epoch.
    pub fn apply_pending_commit(&mut self) -> Res<()> {
        self.group_mut()?
            .apply_pending_commit()
            .map_err(|e| err("apply commit", e))?;
        Ok(())
    }

    /// Drop the pending Commit and the next-epoch secrets it carries.
    ///
    /// RFC 9420 §14 asks for a forked state to be deleted as soon as it is not
    /// needed, so losing a CAS ends here rather than in a retry that keeps the
    /// fork around. Processing the winner's Commit clears the pending on its
    /// own; this exists for the case where the outcome is settled without the
    /// winning message in hand.
    pub fn clear_pending_commit(&mut self) -> Res<()> {
        self.group_mut()?.clear_pending_commit();
        Ok(())
    }

    pub fn has_pending_commit(&mut self) -> Res<bool> {
        Ok(self.group_mut()?.has_pending_commit())
    }

    /// The confirmed epoch. `Group::current_epoch` reads
    /// `self.context().epoch`, and the pending Commit is a separate field, so
    /// this never reports an epoch that only a pending Commit would reach.
    /// The rollback anchor is built on that: it follows this value and nothing
    /// else (design §7.3.3).
    pub fn epoch(&mut self) -> Res<u64> {
        Ok(self.group_mut()?.current_epoch())
    }

    /// Encrypt one application message, consuming the generation `send_position`
    /// reported.
    ///
    /// `authenticated_data` travels in the clear inside the PrivateMessage and
    /// is covered twice: by the sender's signature over FramedContent and by
    /// the AEAD through PrivateContentAAD. That is what lets the receiver treat
    /// a declaration carried in it as the sender's word rather than the
    /// server's.
    pub fn encrypt(&mut self, plaintext: &[u8], authenticated_data: &[u8]) -> Res<Vec<u8>> {
        self.group_mut()?
            .encrypt_application_message(plaintext, authenticated_data.to_vec())
            .map_err(|e| err("encrypt", e))?
            .to_bytes()
            .map_err(|e| err("ciphertext encode", e))
    }

    /// The collect pass of processing: apply `message` to a copy of the group
    /// with every leaf admitted and every proposal let through, report the
    /// leaves it would bring in and the shape of the Commit, and put the group
    /// back exactly as it was. The copy is taken through the storage this
    /// session installed, the same bytes a flush would hand to Go.
    pub fn process_collect(&mut self, message: &[u8]) -> Res<(Vec<Leaf>, CommitShape)> {
        let msg = MlsMessage::from_bytes(message).map_err(|e| err("message decode", e))?;
        let snapshot = self.flush()?;
        let group = self.group_mut()?;
        let before = leaves_of(group);
        self.gate.collect()?;
        self.rules.collect()?;
        let group = self.group_mut()?;
        let applied = group.process_incoming_message(msg).map(|received| {
            let mut after = leaves_of(group);
            after.extend(added_to_a_group_left_behind(&received));
            (after, CommitShape::of(&received, &before))
        });
        self.disarm()?;
        self.load(&snapshot)?;
        let (after, shape) = applied.map_err(|e| err("process", e))?;
        Ok((gate::new_leaves(&before, &after), shape))
    }

    /// Apply one inbound message. A Commit that brings in a leaf the Go side
    /// did not approve for this call is refused, and the session is left
    /// without a group so nothing can build on the half-verified result; the
    /// caller reloads from the record, which never saw it.
    pub fn process(&mut self, message: &[u8]) -> Res<Processed> {
        let msg = MlsMessage::from_bytes(message).map_err(|e| err("message decode", e))?;
        let before = leaves_of(self.group_mut()?);
        let approved = self.arm()?;
        let group = self.group_mut()?;
        let received = group.process_incoming_message(msg);
        self.disarm()?;
        let received = received.map_err(|e| match e {
            MlsError::CantProcessMessageFromSelf => format!("mls: process: {FROM_SELF}"),
            e => err("process", e),
        })?;
        let group = self.group_mut()?;
        let new = gate::new_leaves(&before, &leaves_of(group));
        if let Err(e) = require_approved(&new, &approved) {
            self.group = None;
            return Err(e);
        }
        let group = self.group_mut()?;
        let mut out = Processed {
            epoch: 0,
            removed: false,
            application: None,
            sender_index: 0,
            authenticated_data: Vec::new(),
            key_generation: None,
        };
        match received {
            ReceivedMessage::ApplicationMessage(m) => {
                out.sender_index = m.sender_index;
                out.authenticated_data = m.authenticated_data.clone();
                out.key_generation = m.unauthenticated_key_generation;
                out.application = Some(Zeroizing::new(m.data().to_vec()));
            }
            ReceivedMessage::Commit(c) => {
                out.removed = matches!(c.effect, CommitEffect::Removed { .. });
                out.sender_index = c.committer;
            }
            _ => {}
        }
        out.epoch = group.current_epoch();
        Ok(out)
    }

    /// Where this device's application ratchet stands: the epoch, this
    /// device's leaf, and the generation the next encrypt would take. Read
    /// without advancing any of them.
    ///
    /// The three come back from one call because the caller writes them down as
    /// one position before it encrypts, and three separate reads could each
    /// describe a different moment. Its presence is also the runtime proof that
    /// this build carries both export_key_generation and secret_tree_access:
    /// the upstream cfg on `peek_next_key_generation` requires them together,
    /// so a build missing either does not compile this call.
    ///
    /// Upstream warns the generation "is only safe for synchronous usage of
    /// Group APIs" — it is a read of a counter, not a claim on it, so the
    /// caller owes the exclusion between reading the number and consuming it.
    pub fn send_position(&mut self) -> Res<(u64, u32, u32)> {
        let group = self.group_mut()?;
        let generation = group
            .peek_next_key_generation()
            .map_err(|e| err("peek generation", e))?;
        Ok((
            group.current_epoch(),
            group.current_member_index(),
            generation,
        ))
    }

    /// Consume one application generation without encrypting anything with it.
    ///
    /// This is the recovery half of the send ordering. A generation whose
    /// consumption was written down but whose ciphertext never appeared cannot
    /// be told apart from one that was really used, so it is treated as used:
    /// the key is derived, dropped unused, and the ratchet moves on. The hole
    /// it leaves is ordinary for MLS; handing the number out twice is not.
    ///
    /// The derived key is dropped immediately and is never returned across the
    /// ABI. `next_encryption_key` is what advances `SecretKeyRatchet`, and that
    /// advance is in the snapshot, so the caller has to persist the state
    /// afterwards or the burn did not happen.
    pub fn burn_generation(&mut self) -> Res<()> {
        self.group_mut()?
            .next_encryption_key()
            .map_err(|e| err("burn generation", e))?;
        Ok(())
    }

    /// Push the in-memory group into the storage and hand the bytes back.
    ///
    /// Nothing in mls-rs calls this on its own: encrypting, decrypting and
    /// applying a commit all move the group forward in memory only. Pairing
    /// every advance with a flush is this integration's invariant, not
    /// something the library checks.
    pub fn flush(&mut self) -> Res<Zeroizing<Vec<u8>>> {
        self.group_mut()?
            .write_to_storage()
            .map_err(|e| err("write to storage", e))?;
        self.storage
            .encode()
            .ok_or_else(|| "mls: group state storage stayed empty after a flush".to_string())
    }
}

/// The longest exporter output this crate hands out. The room name key is 32
/// bytes; the bound keeps one call from asking for an unbounded derivation.
pub const MAX_EXPORT_LEN: usize = 64;

fn check_export_len(len: usize) -> Res<()> {
    if len == 0 || len > MAX_EXPORT_LEN {
        return Err(format!(
            "mls: an exported secret is 1..={MAX_EXPORT_LEN} bytes"
        ));
    }
    Ok(())
}

fn exported(secret: &mls_rs_core::secret::Secret) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(secret.as_bytes().to_vec())
}

impl Session {
    /// `MLS-Exporter(label, context, len)` of the confirmed epoch (RFC 9420
    /// §8.5). A pending Commit is not consulted: it lives beside the key
    /// schedule this reads, not in it.
    pub fn export_secret(
        &mut self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Res<Zeroizing<Vec<u8>>> {
        check_export_len(len)?;
        let secret = self
            .group_mut()?
            .export_secret(label, context, len)
            .map_err(|e| err("export secret", e))?;
        Ok(exported(&secret))
    }

    /// The same exporter output for the epoch the pending Commit would
    /// create, and that epoch, **without applying the Commit**.
    ///
    /// mls-rs keeps the next epoch's key schedule inside `pending_commit`
    /// and exposes it only by applying. So this applies the Commit to the
    /// in-memory group, exports, and restores the group from the snapshot it
    /// took first, the same round trip `process_collect` makes. The snapshot
    /// carries `pending_commit`, so the restored group still has the Commit
    /// pending and the confirmed epoch has not moved (RFC 9420 §14). Nothing
    /// is durable here; the caller persists only what it flushes itself.
    pub fn export_pending_secret(
        &mut self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Res<(Zeroizing<Vec<u8>>, u64)> {
        check_export_len(len)?;
        if !self.group_mut()?.has_pending_commit() {
            return Err("mls: no pending commit to export from".to_string());
        }
        let snapshot = self.flush()?;
        let group = self.group_mut()?;
        let next = group
            .apply_pending_commit()
            .map_err(|e| err("apply commit", e))
            .and_then(|_| {
                let secret = group
                    .export_secret(label, context, len)
                    .map_err(|e| err("export secret", e))?;
                Ok((exported(&secret), group.current_epoch()))
            });
        self.load(&snapshot)?;
        next
    }
}

pub fn wire_form(message: &[u8]) -> Res<WireForm> {
    use mls_rs::WireFormat;
    let msg = MlsMessage::from_bytes(message).map_err(|e| err("message decode", e))?;
    Ok(match msg.wire_format() {
        WireFormat::PublicMessage => WireForm::Public,
        WireFormat::PrivateMessage => WireForm::Private,
        WireFormat::Welcome => WireForm::Welcome,
        WireFormat::KeyPackage => WireForm::KeyPackage,
        WireFormat::GroupInfo => WireForm::GroupInfo,
        _ => WireForm::Other,
    })
}

#[cfg(test)]
mod tests {
    use mls_rs::identity::basic::BasicIdentityProvider;

    use super::*;

    /// A KeyPackage whose private entry goes straight back into the same
    /// session, standing in for the Go pool the way a real join would use it.
    fn kp(s: &Session) -> Vec<u8> {
        let g = s.key_package(far_future()).unwrap();
        s.install_key_package(&g.private).unwrap();
        g.message
    }

    fn now() -> u64 {
        MlsTime::now().seconds_since_epoch()
    }

    fn far_future() -> u64 {
        now() + 10 * KEY_PACKAGE_LIFETIME.as_secs()
    }

    fn member(name: &str) -> Session {
        let (sk, pk) = generate_signature_key().unwrap();
        let decl = format!("declaration of {name}");
        Session::new(name.as_bytes(), &sk, &pk, decl.as_bytes()).unwrap()
    }

    fn removal(leaf: &Leaf) -> RemovalApproval {
        RemovalApproval {
            index: leaf.index,
            identity: leaf.identity.clone(),
        }
    }

    fn approval(leaf: &Leaf) -> Approval {
        Approval {
            identity: leaf.identity.clone(),
            signature_key: leaf.signature_key.clone(),
            declaration: leaf.declaration.clone().unwrap_or_default(),
        }
    }

    /// Alice creates a group and adds Bob with Bob's leaf approved, then
    /// confirms. Returns the Welcome.
    fn add(alice: &mut Session, bob: &Session) -> Vec<u8> {
        let kp = kp(bob);
        let leaf = key_package_leaf(&kp).unwrap();
        alice.approve(vec![approval(&leaf)]);
        let (_, welcome, _) = alice.commit_add_members(&[&kp]).unwrap();
        alice.apply_pending_commit().unwrap();
        welcome
    }

    fn identities(s: &mut Session) -> Vec<Vec<u8>> {
        s.roster()
            .unwrap()
            .into_iter()
            .map(|l| l.identity)
            .collect()
    }

    // S-1 unlatches on the confirmed roster, so a built Remove must not show
    // there until it is applied, and must show once it is.
    #[test]
    fn a_pending_remove_leaves_the_leaf_in_the_roster_until_applied() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        add(&mut alice, &member("bob"));
        let bob = alice
            .roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == b"bob")
            .unwrap();

        alice.approve_removals(vec![removal(&bob)]);
        alice.commit_remove_members(&[bob.index]).unwrap();
        assert!(alice.has_pending_commit().unwrap());
        assert_eq!(
            identities(&mut alice),
            vec![b"alice".to_vec(), b"bob".to_vec()]
        );

        alice.apply_pending_commit().unwrap();
        assert_eq!(identities(&mut alice), vec![b"alice".to_vec()]);
    }

    // M4.4: one Commit takes the old leaf out and brings the new device's in,
    // and neither shows in the confirmed roster until it is applied.
    #[test]
    fn a_replace_removes_the_old_leaf_and_adds_the_new_one_in_one_commit() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        add(&mut alice, &member("bob"));
        let old = alice
            .roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == b"bob")
            .unwrap();
        let new_kp = kp(&member("bob2"));
        alice.approve(vec![approval(&key_package_leaf(&new_kp).unwrap())]);
        alice.approve_removals(vec![removal(&old)]);

        let (_, welcome, _) = alice
            .commit_replace_members(&[old.index], &[&new_kp])
            .unwrap();
        assert!(!welcome.is_empty());
        assert_eq!(
            identities(&mut alice),
            vec![b"alice".to_vec(), b"bob".to_vec()]
        );

        alice.apply_pending_commit().unwrap();
        assert_eq!(
            identities(&mut alice),
            vec![b"alice".to_vec(), b"bob2".to_vec()]
        );
    }

    // The old device is removed by the replace, so its group never reaches the
    // new epoch; the collect pass must still report the leaf the Commit adds,
    // or the gate refuses the Commit that tells it it was removed.
    #[test]
    fn a_member_a_replace_removes_still_sees_the_leaf_it_adds() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let welcome = add(&mut alice, &bob);
        let tree = bob.join_collect(&welcome).unwrap();
        bob.approve(tree.iter().map(approval).collect());
        bob.join(&welcome).unwrap();
        let old = alice
            .roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == b"bob")
            .unwrap();
        let new_kp = kp(&member("bob2"));
        alice.approve(vec![approval(&key_package_leaf(&new_kp).unwrap())]);
        alice.approve_removals(vec![removal(&old)]);
        let (commit, _, _) = alice
            .commit_replace_members(&[old.index], &[&new_kp])
            .unwrap();

        let (seen, shape) = bob.process_collect(&commit).unwrap();
        assert_eq!(
            seen.iter().map(|l| l.identity.clone()).collect::<Vec<_>>(),
            vec![b"bob2".to_vec()]
        );
        assert_eq!(shape.removed, vec![old.clone()]);
        bob.approve(seen.iter().map(approval).collect());
        bob.approve_removals(shape.removed.iter().map(removal).collect());
        assert!(bob.process(&commit).unwrap().removed);
    }

    /// Alice, Bob and Carol in one group, every one of them at the same epoch.
    fn three() -> (Session, Session, Session) {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let mut carol = member("carol");
        let (bob_kp, carol_kp) = (kp(&bob), kp(&carol));
        alice.approve(vec![
            approval(&key_package_leaf(&bob_kp).unwrap()),
            approval(&key_package_leaf(&carol_kp).unwrap()),
        ]);
        let (_, welcome, _) = alice.commit_add_members(&[&bob_kp, &carol_kp]).unwrap();
        alice.apply_pending_commit().unwrap();
        for joiner in [&mut bob, &mut carol] {
            let tree = joiner.join_collect(&welcome).unwrap();
            joiner.approve(tree.iter().map(approval).collect());
            joiner.join(&welcome).unwrap();
        }
        (alice, bob, carol)
    }

    fn leaf_named(s: &mut Session, name: &[u8]) -> Leaf {
        s.roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == name)
            .unwrap()
    }

    // Nothing approved is the resting state, so a Remove nobody judged is
    // refused before anything is built.
    #[test]
    fn an_unapproved_remove_builds_nothing() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        add(&mut alice, &member("bob"));
        let bob = leaf_named(&mut alice, b"bob");

        let refused = alice.commit_remove_members(&[bob.index]).unwrap_err();
        assert!(
            refused.contains(crate::authority::NOT_AUTHORIZED),
            "{refused}"
        );
        assert!(!alice.has_pending_commit().unwrap());

        // An approval names a leaf, not a slot: another identity at that
        // index is not what was approved.
        alice.approve_removals(vec![RemovalApproval {
            index: bob.index,
            identity: b"carol".to_vec(),
        }]);
        assert!(alice.commit_remove_members(&[bob.index]).is_err());
        assert!(!alice.has_pending_commit().unwrap());
    }

    // Q4's repro at the library edge: a member whose own client approved the
    // Remove of another member's leaf. The collect pass shows who committed
    // and whom it removed; a receiver that approves nothing refuses the
    // Commit and its group does not move.
    #[test]
    fn a_receiver_refuses_a_remove_it_did_not_approve_and_stays_where_it_was() {
        let (mut alice, mut bob, _carol) = three();
        let carol = leaf_named(&mut bob, b"carol");
        let bob_leaf = leaf_named(&mut bob, b"bob");
        bob.approve_removals(vec![removal(&carol)]);
        let (commit, _) = bob.commit_remove_members(&[carol.index]).unwrap();

        let epoch = alice.epoch().unwrap();
        let (entering, shape) = alice.process_collect(&commit).unwrap();
        assert!(entering.is_empty());
        assert!(shape.is_commit);
        assert_eq!(shape.committer, bob_leaf.index);
        assert_eq!(shape.removed, vec![carol.clone()]);
        assert!(shape.added.is_empty() && shape.other.is_empty());

        let Err(refused) = alice.process(&commit) else {
            panic!("an unapproved remove was applied");
        };
        assert!(
            refused.contains(crate::authority::NOT_AUTHORIZED),
            "{refused}"
        );
        assert_eq!(alice.epoch().unwrap(), epoch);
        assert_eq!(identities(&mut alice).len(), 3);

        // The same Commit with the Remove approved applies.
        alice.approve_removals(vec![removal(&carol)]);
        assert!(!alice.process(&commit).unwrap().removed);
        assert_eq!(alice.epoch().unwrap(), epoch + 1);
    }

    // Only Add and Remove are proposals this integration makes. A Commit that
    // changes the group context (required capabilities, say) is refused by a
    // receiver whatever else was approved.
    #[test]
    fn a_group_context_change_is_refused_by_the_receiver() {
        let (mut alice, mut bob, _carol) = three();
        bob.rules.collect().unwrap();
        let group = bob.group_mut().unwrap();
        let output = group
            .commit_builder()
            .set_group_context_ext(ExtensionList::new())
            .unwrap()
            .build()
            .unwrap();
        bob.rules.enforce(Vec::new()).unwrap();
        let commit = output.commit_message.to_bytes().unwrap();

        let (_, shape) = alice.process_collect(&commit).unwrap();
        assert_eq!(
            shape.other,
            vec![mls_rs_core::group::ProposalType::GROUP_CONTEXT_EXTENSIONS.raw_value()]
        );
        let Err(refused) = alice.process(&commit) else {
            panic!("a group context change was applied");
        };
        assert!(
            refused.contains(crate::authority::NOT_AUTHORIZED),
            "{refused}"
        );
    }

    #[test]
    fn a_replace_with_an_unapproved_leaf_builds_nothing() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        add(&mut alice, &member("bob"));
        let old = alice
            .roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == b"bob")
            .unwrap();
        let new_kp = kp(&member("bob2"));
        assert!(alice
            .commit_replace_members(&[old.index], &[&new_kp])
            .is_err());
        assert!(!alice.has_pending_commit().unwrap());
        assert!(alice.commit_replace_members(&[], &[&new_kp]).is_err());
        assert!(alice.commit_replace_members(&[old.index], &[]).is_err());
    }

    #[test]
    fn a_remove_of_nobody_builds_nothing() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        assert!(alice.commit_remove_members(&[]).is_err());
        assert!(!alice.has_pending_commit().unwrap());
    }

    #[test]
    fn a_key_package_carries_the_declaration_unchanged() {
        let bob = member("bob");
        let leaf = key_package_leaf(&kp(&bob)).unwrap();
        assert_eq!(leaf.identity, b"bob");
        assert_eq!(
            leaf.declaration.as_deref(),
            Some(&b"declaration of bob"[..])
        );
    }

    #[test]
    fn a_key_package_never_outlives_the_cap_it_is_given() {
        let bob = member("bob");
        let cap = now() + 3600;
        let not_after = key_package_not_after(&bob.key_package(cap).unwrap().message).unwrap();
        assert!(not_after <= cap, "{not_after} vs {cap}");
        assert!(not_after + 5 >= cap, "{not_after} vs {cap}");
    }

    #[test]
    fn a_cap_that_has_passed_produces_nothing() {
        let bob = member("bob");
        for cap in [0, now() - 10, now()] {
            let Err(e) = bob.key_package(cap) else {
                panic!("a key package was produced past its cap");
            };
            assert!(e.contains("expired"), "{e}");
            assert_eq!(bob.custody.len(), 0);
        }
    }

    #[test]
    fn generation_leaves_no_private_key_in_the_session() {
        let bob = member("bob");
        let generated = bob.key_package(far_future()).unwrap();
        assert_eq!(bob.custody.len(), 0);
        assert!(!generated.private.is_empty());
        assert!(!generated.reference.is_empty());
    }

    // The case that motivated custody: the session that generated the
    // KeyPackage is gone, and a later one joins from the persisted entry.
    #[test]
    fn a_later_session_joins_from_the_persisted_entry_and_keeps_nothing() {
        let (sk, pk) = generate_signature_key().unwrap();
        let generated = Session::new(b"bob", &sk, &pk, b"declaration of bob")
            .unwrap()
            .key_package(far_future())
            .unwrap();

        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let leaf = key_package_leaf(&generated.message).unwrap();
        alice.approve(vec![approval(&leaf)]);
        let (_, welcome, _) = alice.commit_add_members(&[&generated.message]).unwrap();
        alice.apply_pending_commit().unwrap();
        assert_eq!(
            welcome_key_package_refs(&welcome).unwrap(),
            vec![generated.reference.clone()]
        );

        let mut without = Session::new(b"bob", &sk, &pk, b"declaration of bob").unwrap();
        assert!(without.join_collect(&welcome).is_err());

        let mut later = Session::new(b"bob", &sk, &pk, b"declaration of bob").unwrap();
        later.install_key_package(&generated.private).unwrap();
        let tree = later.join_collect(&welcome).unwrap();
        later.approve(tree.iter().map(approval).collect());
        later.join(&welcome).unwrap();
        assert_eq!(later.epoch().unwrap(), 1);
        assert_eq!(later.custody.len(), 0, "a join must drop the entry");
    }

    #[test]
    fn a_failed_join_drops_the_entry_too() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let welcome = add(&mut alice, &bob);
        bob.approve(Vec::new());
        assert!(bob.join(&welcome).is_err());
        assert_eq!(bob.custody.len(), 0);
    }

    #[test]
    fn something_that_is_not_a_welcome_names_no_key_package() {
        let bob = member("bob");
        assert!(welcome_key_package_refs(&kp(&bob)).unwrap().is_empty());
    }

    #[test]
    fn a_key_package_lives_at_most_the_configured_lifetime() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_after = key_package_not_after(&kp(&member("bob"))).unwrap();
        let lifetime = KEY_PACKAGE_LIFETIME.as_secs();
        assert!(not_after <= now + lifetime + 5, "{not_after} vs {now}");
        assert!(not_after + 5 >= now + lifetime, "{not_after} vs {now}");
    }

    #[test]
    fn an_add_nobody_approved_is_refused_at_build() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let bob = member("bob");
        let kp = kp(&bob);

        assert!(alice.commit_add_members(&[&kp]).is_err());
        assert!(!alice.has_pending_commit().unwrap());
    }

    // Approving Carol does not let Bob in: the gate compares the credential
    // and key it is shown, not "something was approved".
    #[test]
    fn the_gate_refuses_a_leaf_outside_a_narrower_approval() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let bob = member("bob");
        let carol = member("carol");
        let carol_leaf = key_package_leaf(&kp(&carol)).unwrap();

        alice.approve(vec![approval(&carol_leaf)]);
        let e = alice.commit_add_members(&[&kp(&bob)]).unwrap_err();
        assert!(e.contains("not approved"), "{e}");
        assert!(!alice.has_pending_commit().unwrap());
    }

    #[test]
    fn an_approval_is_consumed_by_one_operation() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let bob = member("bob");
        let kp = kp(&bob);
        alice.approve(vec![approval(&key_package_leaf(&kp).unwrap())]);
        alice.commit_add_members(&[&kp]).unwrap();
        alice.clear_pending_commit().unwrap();

        assert!(alice.commit_add_members(&[&kp]).is_err());
    }

    #[test]
    fn one_unapproved_member_refuses_the_whole_add() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let bob = kp(&member("bob"));
        let carol = kp(&member("carol"));
        alice.approve(vec![approval(&key_package_leaf(&bob).unwrap())]);

        assert!(alice.commit_add_members(&[&bob, &carol]).is_err());
        assert!(!alice.has_pending_commit().unwrap());

        alice.approve(vec![
            approval(&key_package_leaf(&bob).unwrap()),
            approval(&key_package_leaf(&carol).unwrap()),
        ]);
        alice.commit_add_members(&[&bob, &carol]).unwrap();
        alice.apply_pending_commit().unwrap();
        assert_eq!(alice.roster_len(), 3);
    }

    // The receiver half of V3 A1. A committer that skipped every check (here,
    // the gated build called directly) adds a leaf with no declaration. The
    // receiver's gate is even told to admit that credential and key, and the
    // leaf is still refused: an approval always names declaration bytes, and
    // "none" matches no bytes.
    #[test]
    fn a_commit_adding_a_leaf_without_a_declaration_is_refused() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let welcome = add(&mut alice, &bob);
        let tree = bob.join_collect(&welcome).unwrap();
        bob.approve(tree.iter().map(approval).collect());
        bob.join(&welcome).unwrap();

        let (sk, pk) = generate_signature_key().unwrap();
        let bare = Session::new(b"mallory", &sk, &pk, &[]).unwrap();
        let kp = kp(&bare);
        let leaf = key_package_leaf(&kp).unwrap();
        assert_eq!(leaf.declaration, None);
        let admit = Approval {
            identity: leaf.identity.clone(),
            signature_key: leaf.signature_key.clone(),
            declaration: Vec::new(),
        };
        alice.approve(vec![admit.clone()]);
        alice.arm().unwrap();
        let (output, _) = alice
            .build_add(vec![MlsMessage::from_bytes(&kp).unwrap()])
            .unwrap();
        alice.disarm().unwrap();
        let commit = output.commit_message.to_bytes().unwrap();

        assert_eq!(
            bob.process_collect(&commit).unwrap().0,
            vec![Leaf { index: 2, ..leaf }]
        );
        bob.approve(vec![admit]);
        let Err(e) = bob.process(&commit) else {
            panic!("a leaf with no declaration was applied");
        };
        assert!(e.contains(gate::NOT_APPROVED), "{e}");
    }

    // The gate sees credential and key only; the declaration bytes Go checked
    // are compared by the session, and a mismatch builds nothing.
    #[test]
    fn an_approval_for_other_declaration_bytes_builds_nothing() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let bob = member("bob");
        let kp = kp(&bob);
        let mut forged = approval(&key_package_leaf(&kp).unwrap());
        forged.declaration = b"what go checked".to_vec();
        alice.approve(vec![forged]);

        let e = alice.commit_add_members(&[&kp]).unwrap_err();
        assert!(e.contains("not approved"), "{e}");
        assert!(!alice.has_pending_commit().unwrap());
    }

    #[test]
    fn a_group_this_keeper_creates_requires_the_extension_capability() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();

        // A client that never heard of the extension. Its leaf is approved,
        // so the refusal below can only be mls-rs enforcing
        // required_capabilities.
        let (sk, pk) = generate_signature_key().unwrap();
        let foreign = Client::builder()
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(signing_identity(b"foreign", &pk), sk.into(), CIPHER_SUITE)
            .build();
        let kp = foreign
            .generate_key_package_message(Default::default(), Default::default(), None)
            .unwrap()
            .to_bytes()
            .unwrap();
        let leaf = key_package_leaf(&kp).unwrap();
        assert_eq!(leaf.declaration, None);

        // The session would refuse this leaf itself for carrying no
        // declaration. Going to the gated build directly, with the leaf
        // admitted, leaves mls-rs as the only thing that can refuse it.
        alice.approve(vec![Approval {
            identity: leaf.identity,
            signature_key: leaf.signature_key,
            declaration: Vec::new(),
        }]);
        alice.arm().unwrap();
        let built = alice.build_add(vec![MlsMessage::from_bytes(&kp).unwrap()]);
        alice.disarm().unwrap();
        let Err(e) = built else {
            panic!("a leaf without the capability was added");
        };
        assert!(e.contains("required extension not found"), "{e}");
    }

    #[test]
    fn a_welcome_needs_every_leaf_of_the_tree_approved() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let generated = bob.key_package(far_future()).unwrap();
        bob.install_key_package(&generated.private).unwrap();
        let leaf = key_package_leaf(&generated.message).unwrap();
        alice.approve(vec![approval(&leaf)]);
        let (_, welcome, _) = alice.commit_add_members(&[&generated.message]).unwrap();
        alice.apply_pending_commit().unwrap();

        let leaves = bob.join_collect(&welcome).unwrap();
        assert_eq!(leaves.len(), 2);

        // Only Bob's own leaf approved: Alice's is not, and the join fails.
        let own: Vec<_> = leaves
            .iter()
            .filter(|l| l.identity == b"bob")
            .map(approval)
            .collect();
        bob.approve(own);
        assert!(bob.join(&welcome).is_err());
        assert!(bob.epoch().is_err(), "a refused join must leave no group");

        // The refused join dropped the entry; a retry takes it from the pool
        // again, as the Go side does.
        bob.install_key_package(&generated.private).unwrap();
        bob.approve(leaves.iter().map(approval).collect());
        bob.join(&welcome).unwrap();
        assert_eq!(bob.epoch().unwrap(), 1);
    }

    #[test]
    fn processing_a_commit_is_refused_unless_its_new_leaf_was_approved() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let welcome = add(&mut alice, &bob);
        let tree = bob.join_collect(&welcome).unwrap();
        bob.approve(tree.iter().map(approval).collect());
        bob.join(&welcome).unwrap();

        let carol = member("carol");
        let kp = kp(&carol);
        alice.approve(vec![approval(&key_package_leaf(&kp).unwrap())]);
        let (commit, _, _) = alice.commit_add_members(&[&kp]).unwrap();

        // The collect pass sees Carol and leaves Bob's group untouched.
        let seen = bob.process_collect(&commit).unwrap().0;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].identity, b"carol");
        assert_eq!(bob.epoch().unwrap(), 1);

        // Without approval the gate refuses inside mls-rs, before anything
        // moved.
        let Err(e) = bob.process(&commit) else {
            panic!("an unapproved leaf was applied");
        };
        assert!(e.contains("not approved"), "{e}");
        assert_eq!(bob.epoch().unwrap(), 1);
    }

    /// Alice and Bob in one group, both confirmed at epoch 1.
    fn pair() -> (Session, Session) {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let welcome = add(&mut alice, &bob);
        let tree = bob.join_collect(&welcome).unwrap();
        bob.approve(tree.iter().map(approval).collect());
        bob.join(&welcome).unwrap();
        (alice, bob)
    }

    /// The same device after a leaf rotation: same identity, a new key and a
    /// new declaration, restored from the state the old session left.
    fn rotated(old: &mut Session, name: &str) -> Session {
        let blob = old.flush().unwrap();
        let (sk, pk) = generate_signature_key().unwrap();
        let decl = format!("rotated declaration of {name}");
        let mut next = Session::new(name.as_bytes(), &sk, &pk, decl.as_bytes()).unwrap();
        next.load(&blob).unwrap();
        next
    }

    fn own_key(s: &mut Session, name: &[u8]) -> Vec<u8> {
        s.roster()
            .unwrap()
            .into_iter()
            .find(|l| l.identity == name)
            .unwrap()
            .signature_key
    }

    // P3: after a rotation the Update carries the active key and its
    // declaration, and a receiver applies it only once that leaf is approved.
    #[test]
    fn an_update_moves_the_group_onto_the_active_leaf_key() {
        let (mut alice, mut bob) = pair();
        let old_key = own_key(&mut bob, b"alice");
        let mut alice = rotated(&mut alice, "alice");

        let (commit, expected) = alice.commit_update().unwrap();
        assert_eq!(expected, 1);

        let seen = bob.process_collect(&commit).unwrap().0;
        assert_eq!(seen.len(), 1, "the replacement leaf must be reported");
        assert_eq!(seen[0].identity, b"alice");
        assert_ne!(seen[0].signature_key, old_key);
        assert_eq!(
            seen[0].declaration.as_deref(),
            Some(&b"rotated declaration of alice"[..])
        );

        let Err(e) = bob.process(&commit) else {
            panic!("a new signature key was applied without approval");
        };
        assert!(
            e.contains("successor") || e.contains(gate::NOT_APPROVED),
            "{e}"
        );
        assert_eq!(bob.epoch().unwrap(), 1);

        bob.approve(seen.iter().map(approval).collect());
        bob.process(&commit).unwrap();
        assert_eq!(bob.epoch().unwrap(), 2);
        assert_ne!(own_key(&mut bob, b"alice"), old_key);

        alice.apply_pending_commit().unwrap();
        let sealed = alice.encrypt(b"hi", b"ad").unwrap();
        let processed = bob.process(&sealed).unwrap();
        assert_eq!(
            processed.application.as_deref().map(|v| &v[..]),
            Some(&b"hi"[..])
        );
    }

    // The sender's own message is refused with the marker the C ABI maps to
    // its own status, and the refusal leaves the receiving side able to open
    // the next message from somebody else.
    #[test]
    fn processing_an_own_message_is_refused_with_the_from_self_marker() {
        let (mut alice, mut bob) = pair();
        let own = alice.encrypt(b"mine", b"ad").unwrap();
        let Err(e) = alice.process(&own) else {
            panic!("a message from this leaf was processed");
        };
        assert!(e.contains(FROM_SELF), "{e}");

        let from_bob = bob.encrypt(b"theirs", b"ad").unwrap();
        let processed = alice.process(&from_bob).unwrap();
        assert_eq!(
            processed.application.as_deref().map(|v| &v[..]),
            Some(&b"theirs"[..])
        );
    }

    const ROOM: &[u8] = b"dragpass room name";

    // The committer reads the new epoch's exporter before its Commit is
    // accepted, and it is the one every member of that epoch derives: the
    // committer after applying, a member who processed the Commit, and a
    // joiner from the Welcome. The pending read leaves the Commit pending and
    // the confirmed epoch where it was.
    #[test]
    fn the_pending_exporter_is_the_next_epochs_exporter_for_everyone() {
        let (mut alice, mut bob) = pair();
        let current = alice.export_secret(ROOM, b"g", 32).unwrap();

        let mut carol = member("carol");
        let kp = kp(&carol);
        alice.approve(vec![approval(&key_package_leaf(&kp).unwrap())]);
        let (commit, welcome, _) = alice.commit_add_members(&[&kp]).unwrap();

        let (pending, epoch) = alice.export_pending_secret(ROOM, b"g", 32).unwrap();
        assert_eq!(epoch, 2);
        assert_ne!(pending, current);
        assert!(alice.has_pending_commit().unwrap());
        assert_eq!(alice.epoch().unwrap(), 1);
        assert_eq!(alice.export_secret(ROOM, b"g", 32).unwrap(), current);

        alice.apply_pending_commit().unwrap();
        assert_eq!(alice.export_secret(ROOM, b"g", 32).unwrap(), pending);

        let seen = bob.process_collect(&commit).unwrap().0;
        bob.approve(seen.iter().map(approval).collect());
        bob.process(&commit).unwrap();
        assert_eq!(bob.export_secret(ROOM, b"g", 32).unwrap(), pending);

        let tree = carol.join_collect(&welcome).unwrap();
        carol.approve(tree.iter().map(approval).collect());
        carol.join(&welcome).unwrap();
        assert_eq!(carol.export_secret(ROOM, b"g", 32).unwrap(), pending);

        // The context separates two conversations' names in one epoch.
        assert_ne!(carol.export_secret(ROOM, b"h", 32).unwrap(), pending);
    }

    // A group create's pending Commit exports epoch 1, which is what the
    // first member joins at.
    #[test]
    fn a_creates_pending_exporter_is_epoch_one() {
        let mut alice = member("alice");
        alice.create_group(b"g").unwrap();
        let mut bob = member("bob");
        let kp = kp(&bob);
        alice.approve(vec![approval(&key_package_leaf(&kp).unwrap())]);
        let (_, welcome, _) = alice.commit_add_members(&[&kp]).unwrap();
        let (pending, epoch) = alice.export_pending_secret(ROOM, b"g", 32).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(alice.epoch().unwrap(), 0);

        let tree = bob.join_collect(&welcome).unwrap();
        bob.approve(tree.iter().map(approval).collect());
        bob.join(&welcome).unwrap();
        assert_eq!(bob.export_secret(ROOM, b"g", 32).unwrap(), pending);
    }

    #[test]
    fn an_export_is_bounded_and_needs_a_pending_commit_for_the_next_epoch() {
        let (mut alice, _) = pair();
        assert!(alice.export_secret(ROOM, b"g", 0).is_err());
        assert!(alice.export_secret(ROOM, b"g", MAX_EXPORT_LEN + 1).is_err());
        let Err(e) = alice.export_pending_secret(ROOM, b"g", 32) else {
            panic!("a next-epoch secret without a pending commit");
        };
        assert!(e.contains("no pending commit"), "{e}");
    }

    // Without a rotation an Update changes neither the key nor the
    // declaration, so a receiver needs no approval for it.
    #[test]
    fn an_update_without_a_rotation_keeps_the_leaf_key() {
        let (mut alice, mut bob) = pair();
        let before = own_key(&mut bob, b"alice");
        let (commit, _) = alice.commit_update().unwrap();
        assert!(bob.process_collect(&commit).unwrap().0.is_empty());
        bob.process(&commit).unwrap();
        assert_eq!(own_key(&mut bob, b"alice"), before);
    }
}
