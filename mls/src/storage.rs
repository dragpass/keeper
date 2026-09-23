// storage.rs — the GroupStateStorage mls-rs writes into, and the framing that
// turns what it wrote into the one opaque blob Keeper stores; and the
// KeyPackageStorage that hands KeyPackage private keys to Go and back.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use mls_rs_core::crypto::HpkeSecretKey;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

/// Magic and version of the blob this module produces. It is not an mls-rs
/// format: mls-rs keeps `Snapshot` and `Group::snapshot()` `pub(crate)`, so the
/// only bytes we can ever hold are the ones handed to `write`, and those arrive
/// as a state plus a set of prior epochs rather than as one serialized object.
/// Framing them ourselves is what lets `Record.GroupState` stay a single field.
const MAGIC: &[u8; 8] = b"DPMLSGS1";

#[derive(Default)]
struct Inner {
    group_id: Vec<u8>,
    state: Option<Zeroizing<Vec<u8>>>,
    epochs: BTreeMap<u64, Zeroizing<Vec<u8>>>,
}

/// RecordStorage is the seam between mls-rs and Keeper's chat state file.
///
/// mls-rs never persists on its own: the group changes in memory and reaches
/// this storage only when the caller invokes `Group::write_to_storage`. That is
/// what lets the Go side decide when the write happens, which in turn is what
/// makes an ordering discipline possible at all.
///
/// Durability and atomicity are deliberately NOT here. The trait's own doc says
/// a `write` "should optimally be a single atomic transaction" — optimally, not
/// MUST — so the obligation falls on the implementer. This implementation only
/// accumulates; the atomic unit is Keeper's whole-file replacement
/// (temp -> fsync -> rename -> directory fsync) on the Go side, which already
/// has that property for the record this blob lives in.
#[derive(Clone, Default)]
pub struct RecordStorage(Arc<Mutex<Inner>>);

impl RecordStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize everything mls-rs has pushed down so far. None means the group
    /// has never been written, which is not the same as an empty group.
    pub fn encode(&self) -> Option<Zeroizing<Vec<u8>>> {
        let inner = self.0.lock().expect("group state storage mutex poisoned");
        let state = inner.state.as_ref()?;

        let mut out = Zeroizing::new(Vec::with_capacity(state.len() + 64));
        out.extend_from_slice(MAGIC);
        put_bytes(&mut out, &inner.group_id);
        put_bytes(&mut out, state);
        out.extend_from_slice(&(inner.epochs.len() as u32).to_be_bytes());
        for (id, data) in inner.epochs.iter() {
            out.extend_from_slice(&id.to_be_bytes());
            put_bytes(&mut out, data);
        }
        Some(out)
    }

    /// Seed the storage from a blob so `Client::load_group` finds a group.
    pub fn decode_into(&self, blob: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut cur = Cursor::new(blob);
        if cur.take(MAGIC.len())? != MAGIC {
            return Err("chat state MLS blob has an unknown magic");
        }
        let group_id = cur.take_prefixed()?.to_vec();
        let state = Zeroizing::new(cur.take_prefixed()?.to_vec());
        let count = cur.take_u32()?;
        let mut epochs = BTreeMap::new();
        for _ in 0..count {
            let id = cur.take_u64()?;
            epochs.insert(id, Zeroizing::new(cur.take_prefixed()?.to_vec()));
        }
        if !cur.done() {
            return Err("chat state MLS blob has trailing bytes");
        }

        let mut inner = self.0.lock().expect("group state storage mutex poisoned");
        inner.group_id = group_id.clone();
        inner.state = Some(state);
        inner.epochs = epochs;
        Ok(group_id)
    }
}

impl GroupStateStorage for RecordStorage {
    type Error = Infallible;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let inner = self.0.lock().expect("group state storage mutex poisoned");
        if inner.group_id != group_id {
            return Ok(None);
        }
        Ok(inner.state.clone())
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let inner = self.0.lock().expect("group state storage mutex poisoned");
        if inner.group_id != group_id {
            return Ok(None);
        }
        Ok(inner.epochs.get(&epoch_id).cloned())
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let mut inner = self.0.lock().expect("group state storage mutex poisoned");
        inner.group_id = state.id;
        inner.state = Some(state.data);
        for rec in epoch_inserts.into_iter().chain(epoch_updates) {
            inner.epochs.insert(rec.id, rec.data);
        }
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let inner = self.0.lock().expect("group state storage mutex poisoned");
        if inner.group_id != group_id {
            return Ok(None);
        }
        Ok(inner.epochs.keys().next_back().copied())
    }
}

/// Magic and version of one KeyPackage private entry as Go stores it. Go treats
/// the bytes as opaque; only this module reads them.
const KEY_PACKAGE_MAGIC: &[u8; 8] = b"DPMLSKP1";

/// KeyPackageCustody is where mls-rs puts a KeyPackage's private keys (the HPKE
/// init key and the leaf encryption key) when it generates one, and where it
/// looks for them when a Welcome arrives.
///
/// It is a hand-off point, not a store. Persistence belongs to the Go side,
/// which seals every entry into the owner's chat state directory, so a
/// Welcome that arrives in a later process can still be joined. Generation
/// takes the new entry straight back out (`take`), so a session never keeps a
/// private key it produced; a join puts back exactly the one entry the Welcome
/// names (`install`), and `clear` drops it once that join is over. mls-rs's own
/// `delete` after a successful join lands here too, and it is not durable:
/// the durable delete is the Go side's, ordered after the group state write.
///
/// Dropping an entry zeroizes its keys: `HpkeSecretKey` is `ZeroizeOnDrop`.
#[derive(Clone, Default)]
pub struct KeyPackageCustody(Arc<Mutex<BTreeMap<Vec<u8>, KeyPackageData>>>);

impl KeyPackageCustody {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove the one entry a generation just inserted, framed for Go, with
    /// its KeyPackage reference. Anything but exactly one entry is an error:
    /// it would mean a key the caller is not about to persist.
    pub fn take(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), &'static str> {
        let mut inner = self.0.lock().expect("key package custody mutex poisoned");
        if inner.len() != 1 {
            inner.clear();
            return Err("mls: key package custody did not hold exactly one new entry");
        }
        let (reference, data) = inner
            .pop_first()
            .ok_or("mls: key package custody did not hold exactly one new entry")?;
        let entry = encode_key_package_entry(&reference, &data);
        Ok((reference, entry))
    }

    /// Put one entry Go kept back, for the join that needs it. Returns its
    /// reference.
    pub fn install(&self, entry: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (reference, data) = decode_key_package_entry(entry)?;
        let mut inner = self.0.lock().expect("key package custody mutex poisoned");
        inner.clear();
        inner.insert(reference.clone(), data);
        Ok(reference)
    }

    pub fn clear(&self) {
        self.0
            .lock()
            .expect("key package custody mutex poisoned")
            .clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0
            .lock()
            .expect("key package custody mutex poisoned")
            .len()
    }
}

impl KeyPackageStorage for KeyPackageCustody {
    type Error = Infallible;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.0
            .lock()
            .expect("key package custody mutex poisoned")
            .remove(id);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        self.0
            .lock()
            .expect("key package custody mutex poisoned")
            .insert(id, pkg);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        Ok(self
            .0
            .lock()
            .expect("key package custody mutex poisoned")
            .get(id)
            .cloned())
    }
}

fn encode_key_package_entry(reference: &[u8], data: &KeyPackageData) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        KEY_PACKAGE_MAGIC.len()
            + 4 * 4
            + reference.len()
            + data.key_package_bytes.len()
            + data.init_key.len()
            + data.leaf_node_key.len()
            + 8,
    ));
    out.extend_from_slice(KEY_PACKAGE_MAGIC);
    put_bytes(&mut out, reference);
    put_bytes(&mut out, &data.key_package_bytes);
    put_bytes(&mut out, &data.init_key);
    put_bytes(&mut out, &data.leaf_node_key);
    out.extend_from_slice(&data.expiration.to_be_bytes());
    out
}

// The messages never describe the entry's contents or size: it carries two
// private keys.
fn decode_key_package_entry(entry: &[u8]) -> Result<(Vec<u8>, KeyPackageData), &'static str> {
    let malformed = "mls: key package entry is malformed";
    let mut cur = Cursor::new(entry);
    if cur.take(KEY_PACKAGE_MAGIC.len()).map_err(|_| malformed)? != KEY_PACKAGE_MAGIC {
        return Err(malformed);
    }
    let reference = cur.take_prefixed().map_err(|_| malformed)?.to_vec();
    let key_package = cur.take_prefixed().map_err(|_| malformed)?.to_vec();
    let init_key = HpkeSecretKey::from(cur.take_prefixed().map_err(|_| malformed)?.to_vec());
    let leaf_node_key = HpkeSecretKey::from(cur.take_prefixed().map_err(|_| malformed)?.to_vec());
    let expiration = cur.take_u64().map_err(|_| malformed)?;
    if !cur.done() || reference.is_empty() || key_package.is_empty() {
        return Err(malformed);
    }
    Ok((
        reference,
        KeyPackageData::new(key_package, init_key, leaf_node_key, expiration),
    ))
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn done(&self) -> bool {
        self.at == self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .at
            .checked_add(n)
            .ok_or("chat state MLS blob is truncated")?;
        if end > self.buf.len() {
            return Err("chat state MLS blob is truncated");
        }
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn take_u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn take_u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn take_prefixed(&mut self) -> Result<&'a [u8], &'static str> {
        let n = self.take_u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(id: &[u8], data: &[u8]) -> GroupState {
        GroupState {
            id: id.to_vec(),
            data: Zeroizing::new(data.to_vec()),
        }
    }

    #[test]
    fn round_trips_state_and_epochs() {
        let mut s = RecordStorage::new();
        s.write(
            state(b"gid", b"body"),
            vec![EpochRecord::new(1, Zeroizing::new(b"e1".to_vec()))],
            vec![],
        )
        .unwrap();
        let blob = s.encode().unwrap();

        let loaded = RecordStorage::new();
        assert_eq!(loaded.decode_into(&blob).unwrap(), b"gid".to_vec());
        assert_eq!(loaded.state(b"gid").unwrap().unwrap().to_vec(), b"body");
        assert_eq!(loaded.epoch(b"gid", 1).unwrap().unwrap().to_vec(), b"e1");
        assert_eq!(loaded.max_epoch_id(b"gid").unwrap(), Some(1));
    }

    #[test]
    fn unwritten_storage_encodes_to_nothing() {
        assert!(RecordStorage::new().encode().is_none());
    }

    #[test]
    fn a_different_group_id_is_a_miss_rather_than_a_wrong_answer() {
        let mut s = RecordStorage::new();
        s.write(state(b"gid", b"body"), vec![], vec![]).unwrap();
        assert!(s.state(b"other").unwrap().is_none());
        assert!(s.max_epoch_id(b"other").unwrap().is_none());
    }

    fn key_package_data() -> KeyPackageData {
        KeyPackageData::new(
            b"key package".to_vec(),
            HpkeSecretKey::from(b"init".to_vec()),
            HpkeSecretKey::from(b"leaf".to_vec()),
            1_791_591_000,
        )
    }

    #[test]
    fn a_generated_entry_is_taken_out_and_installs_back_unchanged() {
        let mut custody = KeyPackageCustody::new();
        custody.insert(b"ref".to_vec(), key_package_data()).unwrap();

        let (reference, entry) = custody.take().unwrap();
        assert_eq!(reference, b"ref");
        assert_eq!(custody.len(), 0, "take must leave nothing behind");

        let other = KeyPackageCustody::new();
        assert_eq!(other.install(&entry).unwrap(), b"ref");
        assert!(other.get(b"ref").unwrap() == Some(key_package_data()));
        other.clear();
        assert_eq!(other.len(), 0);
    }

    #[test]
    fn take_refuses_anything_but_exactly_one_entry() {
        let mut custody = KeyPackageCustody::new();
        assert!(custody.take().is_err());
        custody.insert(b"a".to_vec(), key_package_data()).unwrap();
        custody.insert(b"b".to_vec(), key_package_data()).unwrap();
        assert!(custody.take().is_err());
        assert_eq!(custody.len(), 0, "a refused take must not keep the keys");
    }

    #[test]
    fn a_damaged_entry_is_refused_without_describing_it() {
        let mut custody = KeyPackageCustody::new();
        custody.insert(b"ref".to_vec(), key_package_data()).unwrap();
        let (_, entry) = custody.take().unwrap();

        let mut longer = entry.to_vec();
        longer.push(0);
        let mut other_magic = entry.to_vec();
        other_magic[0] ^= 1;
        for bad in [
            &entry[..entry.len() - 1],
            &longer[..],
            &other_magic[..],
            b"",
        ] {
            let e = KeyPackageCustody::new().install(bad).unwrap_err();
            assert_eq!(e, "mls: key package entry is malformed");
        }
    }

    #[test]
    fn truncated_and_tampered_blobs_are_refused() {
        let mut s = RecordStorage::new();
        s.write(state(b"gid", b"body"), vec![], vec![]).unwrap();
        let blob = s.encode().unwrap();

        assert!(RecordStorage::new()
            .decode_into(&blob[..blob.len() - 1])
            .is_err());
        assert!(RecordStorage::new().decode_into(b"nope").is_err());

        let mut longer = blob.to_vec();
        longer.push(0);
        assert!(RecordStorage::new().decode_into(&longer).is_err());
    }
}
