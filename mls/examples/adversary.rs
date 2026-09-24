// adversary.rs — a test-only MLS client that breaks this integration's rules
// on purpose.
//
// The Keeper refuses to build a Commit its own rules forbid, so the receiving
// half of those rules can only be tested against a client that is not a
// Keeper. This is one: mls-rs used directly, with its DefaultMlsRules (every
// proposal allowed) and a BasicIdentityProvider (every credential accepted),
// so the Commits it produces are cryptographically valid and signed by a real
// member of the group, and nothing here judges what they do. The Go tests
// (internal/keystore/dispatch/mls_adversary_e2e_cgo_test.go and the
// killharness) drive it over stdin and stdout and feed what it builds to
// normal Keepers through their real receive path.
//
// It is never part of a release: an example is built only on request, and
// nothing links it into the static library.
//
// # Protocol
//
// One command per line, fields separated by spaces, bytes as lowercase hex,
// "-" for none. Every answer is one line: "ok" and its fields, or "err" and a
// message.
//
//     identity <identity> <secret> <public> <declaration> <lifetime_secs> <roles 0|1>
//     key-package                  -> ok <key package message>
//     key-package-entry            -> ok <Keeper pool entry> <reference> <not_after>
//     join <welcome>               -> ok <epoch>
//     process <message>            -> ok <epoch>
//     commit <adds> <removes> <roles> <aad> <apply 0|1>
//                                  -> ok <commit> <welcome>
//     roster                       -> ok <index>:<identity>,...
//     epoch                        -> ok <epoch>
//
// <adds> is key package messages joined with ",", <removes> leaf indices
// joined with ",". <roles> is a roles payload the Commit's group context
// change sets (0xF0D1), <aad> its authenticated data. With apply 1 the Commit
// is applied here too; otherwise this client stays at its epoch.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mls_rs::client_builder::{
    BaseConfig, WithCryptoProvider, WithIdentityProvider, WithKeyPackageRepo,
};
use mls_rs::extension::ExtensionType;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{CipherSuite, Client, Extension, ExtensionList, Group, MlsMessage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

// These mirror the library's private constants (gate.rs, roles.rs,
// session.rs, storage.rs). A client that disagreed with them would be refused
// for the wrong reason, which the tests guard against with a positive control:
// the same client's lawful Commits are applied.
const LEAF_DECLARATION_EXTENSION: u16 = 0xF0D0;
const ROLES_EXTENSION: u16 = 0xF0D1;
const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;
const KEY_PACKAGE_MAGIC: &[u8; 8] = b"DPMLSKP1";

/// The key package store: the one this client joins from, and where
/// `key-package-entry` reads the entry it frames for a Keeper pool.
#[derive(Clone, Default)]
struct Repo(Arc<Mutex<BTreeMap<Vec<u8>, KeyPackageData>>>);

impl KeyPackageStorage for Repo {
    type Error = Infallible;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        if let Ok(mut inner) = self.0.lock() {
            inner.remove(id);
        }
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        if let Ok(mut inner) = self.0.lock() {
            inner.insert(id, pkg);
        }
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        Ok(self.0.lock().ok().and_then(|inner| inner.get(id).cloned()))
    }
}

type Cfg = WithKeyPackageRepo<
    Repo,
    WithIdentityProvider<BasicIdentityProvider, WithCryptoProvider<RustCryptoProvider, BaseConfig>>,
>;

struct Adversary {
    client: Client<Cfg>,
    repo: Repo,
    leaf_extensions: ExtensionList,
    group: Option<Group<Cfg>>,
}

type Res<T> = Result<T, String>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    if s == "-" {
        return Ok(Vec::new());
    }
    if !s.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "bad hex".to_string())
        })
        .collect()
}

fn list(s: &str) -> Vec<&str> {
    if s == "-" {
        Vec::new()
    } else {
        s.split(',').collect()
    }
}

fn e(context: &str, err: impl std::fmt::Display) -> String {
    format!("{context}: {err}")
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Res<()> {
    let len = u32::try_from(b.len()).map_err(|_| "entry field too long".to_string())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

impl Adversary {
    fn new(args: &[&str]) -> Res<Self> {
        let [identity, secret, public, declaration, lifetime, roles] = args else {
            return Err("identity takes six fields".into());
        };
        let lifetime: u64 = lifetime.parse().map_err(|_| "bad lifetime".to_string())?;
        let credential = BasicCredential::new(unhex(identity)?);
        let signing = SigningIdentity::new(credential.into_credential(), unhex(public)?.into());
        let repo = Repo::default();
        let mut builder = Client::builder()
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(BasicIdentityProvider::new())
            .key_package_repo(repo.clone())
            .extension_type(ExtensionType::new(LEAF_DECLARATION_EXTENSION));
        if *roles == "1" {
            builder = builder.extension_type(ExtensionType::new(ROLES_EXTENSION));
        }
        let client = builder
            .key_package_lifetime(Duration::from_secs(lifetime))
            .signing_identity(signing, unhex(secret)?.into(), CIPHER_SUITE)
            .build();
        let mut leaf_extensions = ExtensionList::new();
        leaf_extensions.set(Extension::new(
            ExtensionType::new(LEAF_DECLARATION_EXTENSION),
            unhex(declaration)?,
        ));
        Ok(Self {
            client,
            repo,
            leaf_extensions,
            group: None,
        })
    }

    fn group(&mut self) -> Res<&mut Group<Cfg>> {
        self.group.as_mut().ok_or_else(|| "no group".to_string())
    }

    fn key_package(&self) -> Res<Vec<u8>> {
        self.client
            .generate_key_package_message(Default::default(), self.leaf_extensions.clone(), None)
            .map_err(|err| e("key package", err))?
            .to_bytes()
            .map_err(|err| e("key package encode", err))
    }

    /// One key package, framed as a Keeper pool entry the way storage.rs
    /// frames one: magic, then length-prefixed reference, key package, init
    /// key and leaf key, then the expiration.
    fn key_package_entry(&self) -> Res<String> {
        if let Ok(mut inner) = self.repo.0.lock() {
            inner.clear();
        }
        self.key_package()?;
        let inner = self
            .repo
            .0
            .lock()
            .map_err(|_| "repo poisoned".to_string())?;
        let (reference, data) = inner
            .iter()
            .next()
            .ok_or_else(|| "no key package entry".to_string())?;
        let mut out = KEY_PACKAGE_MAGIC.to_vec();
        put_bytes(&mut out, reference)?;
        put_bytes(&mut out, &data.key_package_bytes)?;
        put_bytes(&mut out, &data.init_key)?;
        put_bytes(&mut out, &data.leaf_node_key)?;
        out.extend_from_slice(&data.expiration.to_be_bytes());
        Ok(format!(
            "{} {} {}",
            hex(&out),
            hex(reference),
            data.expiration
        ))
    }

    fn join(&mut self, welcome: &str) -> Res<u64> {
        let msg = MlsMessage::from_bytes(&unhex(welcome)?).map_err(|err| e("welcome", err))?;
        let (group, _) = self
            .client
            .join_group(None, &msg, None)
            .map_err(|err| e("join", err))?;
        let epoch = group.current_epoch();
        self.group = Some(group);
        Ok(epoch)
    }

    fn process(&mut self, message: &str) -> Res<u64> {
        let msg = MlsMessage::from_bytes(&unhex(message)?).map_err(|err| e("message", err))?;
        let group = self.group()?;
        group
            .process_incoming_message(msg)
            .map_err(|err| e("process", err))?;
        Ok(group.current_epoch())
    }

    fn commit(&mut self, args: &[&str]) -> Res<String> {
        let [adds, removes, roles, aad, apply] = args else {
            return Err("commit takes five fields".into());
        };
        let mut key_packages = Vec::new();
        for kp in list(adds) {
            key_packages
                .push(MlsMessage::from_bytes(&unhex(kp)?).map_err(|err| e("key package", err))?);
        }
        let mut indices = Vec::new();
        for index in list(removes) {
            indices.push(index.parse::<u32>().map_err(|_| "bad index".to_string())?);
        }
        let roles = unhex(roles)?;
        let aad = unhex(aad)?;
        let group = self.group()?;
        let mut context = None;
        if !roles.is_empty() {
            let mut extensions = group.context().extensions.clone();
            extensions.set(Extension::new(ExtensionType::new(ROLES_EXTENSION), roles));
            context = Some(extensions);
        }
        let mut builder = group.commit_builder();
        for index in indices {
            builder = builder
                .remove_member(index)
                .map_err(|err| e("remove", err))?;
        }
        for kp in key_packages {
            builder = builder.add_member(kp).map_err(|err| e("add", err))?;
        }
        if let Some(extensions) = context {
            builder = builder
                .set_group_context_ext(extensions)
                .map_err(|err| e("group context", err))?;
        }
        if !aad.is_empty() {
            builder = builder.authenticated_data(aad);
        }
        let output = builder.build().map_err(|err| e("commit build", err))?;
        if *apply == "1" {
            group
                .apply_pending_commit()
                .map_err(|err| e("apply", err))?;
        } else {
            group.clear_pending_commit();
        }
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|err| e("commit encode", err))?;
        let welcome = match output.welcome_messages.first() {
            Some(w) => hex(&w.to_bytes().map_err(|err| e("welcome encode", err))?),
            None => "-".to_string(),
        };
        Ok(format!("{} {welcome}", hex(&commit)))
    }

    fn roster(&mut self) -> Res<String> {
        let group = self.group()?;
        let members: Vec<String> = group
            .roster()
            .members_iter()
            .map(|m| {
                let id = m
                    .signing_identity
                    .credential
                    .as_basic()
                    .map(|b| hex(&b.identifier))
                    .unwrap_or_else(|| "-".to_string());
                format!("{}:{id}", m.index)
            })
            .collect();
        Ok(members.join(","))
    }
}

fn answer(adversary: &mut Option<Adversary>, line: &str) -> Res<String> {
    let mut fields = line.split_whitespace();
    let op = fields.next().unwrap_or_default();
    let args: Vec<&str> = fields.collect();
    if op == "identity" {
        *adversary = Some(Adversary::new(&args)?);
        return Ok(String::new());
    }
    let a = adversary
        .as_mut()
        .ok_or_else(|| "identity first".to_string())?;
    match (op, args.as_slice()) {
        ("key-package", []) => Ok(hex(&a.key_package()?)),
        ("key-package-entry", []) => a.key_package_entry(),
        ("join", [welcome]) => Ok(a.join(welcome)?.to_string()),
        ("process", [message]) => Ok(a.process(message)?.to_string()),
        ("commit", rest) => a.commit(rest),
        ("roster", []) => a.roster(),
        ("epoch", []) => Ok(a.group()?.current_epoch().to_string()),
        _ => Err(format!("unknown command {op}")),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut adversary = None;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let reply = match answer(&mut adversary, line.trim()) {
            Ok(out) if out.is_empty() => "ok".to_string(),
            Ok(out) => format!("ok {out}"),
            Err(err) => format!("err {}", err.replace('\n', " ")),
        };
        if writeln!(stdout, "{reply}")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            break;
        }
    }
}
