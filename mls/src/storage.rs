// storage.rs — the GroupStateStorage mls-rs writes into, and the framing that
// turns what it wrote into the one opaque blob Keeper stores.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
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
