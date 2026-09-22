// session.rs — one conversation's MLS client and group, and the policy this
// integration fixes rather than inherits.

use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithMlsRules,
};
use mls_rs::group::{CommitEffect, ReceivedMessage};
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{DefaultMlsRules, EncryptionOptions};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use zeroize::Zeroizing;

use crate::storage::RecordStorage;

/// RFC 9420 ciphersuite 1. The rustcrypto provider implements 1, 2, 3 and 7;
/// 4, 5 and 6 are absent because the curves behind them are not implemented
/// there. Pinned to one value here because a skeleton that negotiates has an
/// untested branch, not because the others are ruled out.
pub const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

type Config = WithMlsRules<
    DefaultMlsRules,
    WithGroupStateStorage<
        RecordStorage,
        WithIdentityProvider<
            BasicIdentityProvider,
            WithCryptoProvider<RustCryptoProvider, BaseConfig>,
        >,
    >,
>;

pub struct Session {
    client: Client<Config>,
    storage: RecordStorage,
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

pub struct Processed {
    pub epoch: u64,
    pub removed: bool,
    pub application: Option<Zeroizing<Vec<u8>>>,
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

impl Session {
    pub fn new(identity: &[u8], secret_key: &[u8], public_key: &[u8]) -> Res<Self> {
        let storage = RecordStorage::new();
        let signing_identity = SigningIdentity::new(
            BasicCredential::new(identity.to_vec()).into_credential(),
            public_key.to_vec().into(),
        );

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
        let rules = DefaultMlsRules::new()
            .with_encryption_options(EncryptionOptions::new(false, PaddingMode::StepFunction));

        let client = Client::builder()
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(BasicIdentityProvider::new())
            .group_state_storage(storage.clone())
            .mls_rules(rules)
            .signing_identity(signing_identity, secret_key.to_vec().into(), CIPHER_SUITE)
            .build();

        Ok(Self {
            client,
            storage,
            group: None,
        })
    }

    pub fn key_package(&self) -> Res<Vec<u8>> {
        self.client
            .generate_key_package_message(Default::default(), Default::default(), None)
            .map_err(|e| err("key package", e))?
            .to_bytes()
            .map_err(|e| err("key package encode", e))
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Res<()> {
        self.group = Some(
            self.client
                .create_group_with_id(
                    group_id.to_vec(),
                    Default::default(),
                    Default::default(),
                    None,
                )
                .map_err(|e| err("create group", e))?,
        );
        Ok(())
    }

    pub fn join(&mut self, welcome: &[u8]) -> Res<()> {
        let msg = MlsMessage::from_bytes(welcome).map_err(|e| err("welcome decode", e))?;
        let (group, _) = self
            .client
            .join_group(None, &msg, None)
            .map_err(|e| err("join group", e))?;
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

    fn group_mut(&mut self) -> Res<&mut Group<Config>> {
        self.group
            .as_mut()
            .ok_or_else(|| "mls: session has no group".to_string())
    }

    pub fn add_member(&mut self, key_package: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
        let kp = MlsMessage::from_bytes(key_package).map_err(|e| err("key package decode", e))?;
        let group = self.group_mut()?;
        let output = group
            .commit_builder()
            .add_member(kp)
            .map_err(|e| err("add member", e))?
            .build()
            .map_err(|e| err("commit build", e))?;
        group
            .apply_pending_commit()
            .map_err(|e| err("apply commit", e))?;
        let welcome = match output.welcome_messages.first() {
            Some(w) => w.to_bytes().map_err(|e| err("welcome encode", e))?,
            None => Vec::new(),
        };
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| err("commit encode", e))?;
        Ok((commit, welcome))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Res<Vec<u8>> {
        self.group_mut()?
            .encrypt_application_message(plaintext, Vec::new())
            .map_err(|e| err("encrypt", e))?
            .to_bytes()
            .map_err(|e| err("ciphertext encode", e))
    }

    pub fn process(&mut self, message: &[u8]) -> Res<Processed> {
        let msg = MlsMessage::from_bytes(message).map_err(|e| err("message decode", e))?;
        let group = self.group_mut()?;
        let received = group
            .process_incoming_message(msg)
            .map_err(|e| err("process", e))?;
        let (removed, application) = match received {
            ReceivedMessage::ApplicationMessage(m) => {
                (false, Some(Zeroizing::new(m.data().to_vec())))
            }
            ReceivedMessage::Commit(c) => (matches!(c.effect, CommitEffect::Removed { .. }), None),
            _ => (false, None),
        };
        Ok(Processed {
            epoch: group.current_epoch(),
            removed,
            application,
        })
    }

    /// The next application generation this device would consume, read without
    /// advancing. Its presence is also the runtime proof that this build
    /// carries both export_key_generation and secret_tree_access: the upstream
    /// cfg on `peek_next_key_generation` requires them together, so a build
    /// missing either does not compile this call.
    ///
    /// Upstream warns the value "is only safe for synchronous usage of Group
    /// APIs" — it is a read of a counter, not a claim on it, so the caller owes
    /// the exclusion between reading the number and consuming it.
    pub fn peek_generation(&mut self) -> Res<u32> {
        self.group_mut()?
            .peek_next_key_generation()
            .map_err(|e| err("peek generation", e))
    }

    pub fn epoch(&mut self) -> Res<u64> {
        Ok(self.group_mut()?.current_epoch())
    }

    pub fn member_index(&mut self) -> Res<u32> {
        Ok(self.group_mut()?.current_member_index())
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
