// dragpass-mls — the C ABI Keeper's Go code calls mls-rs through.
//
// Memory, stated plainly because the threat model has to quote it:
//
//   - Buffers this library returns are Rust heap allocations. Go copies out of
//     them and calls dpmls_buf_free, which zeroes the bytes before releasing
//     them. Nothing here is freed by Go's allocator and nothing here is freed
//     twice: a freed DpBuf is left null.
//   - Buffers Go passes in are borrowed for the duration of one call and
//     copied. This library never keeps a pointer to Go memory past a return,
//     which is what cgo's pointer-passing rules require. Wiping those is the Go
//     side's job; this side cannot reach them afterwards.
//   - mls-rs protects key material with zeroize: the secret is overwritten when
//     the value carrying it is dropped. That is one buffer at one moment. It
//     does not cover copies made along the way, the old allocation a Vec
//     abandons when it grows, a page the OS wrote to swap, or the image in a
//     core dump. Rust's global allocator is a plain heap here, not mlocked and
//     not guarded, so Keeper's memguard arena does not extend over any of it.
//
// Every entry point catches unwinds. A panic that crossed this boundary would
// be undefined behaviour, and since Rust 1.81 an abort — which for a
// native-messaging daemon means the process dies on input the extension merely
// got wrong.

mod gate;
mod session;
mod storage;

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use session::{Processed, Session, WireForm};
use zeroize::{Zeroize, Zeroizing};

pub const DPMLS_OK: i32 = 0;
pub const DPMLS_ERR: i32 = -1;
pub const DPMLS_ERR_PANIC: i32 = -2;
pub const DPMLS_ERR_ARG: i32 = -3;
/// A leaf the Go side did not approve tried to enter the group, and the
/// operation was refused with nothing applied.
pub const DPMLS_ERR_UNTRUSTED: i32 = -4;

/// A buffer owned by this library until dpmls_buf_free takes it back. cap is
/// carried because releasing a Vec needs the capacity it was allocated with,
/// not the length it ended up holding.
#[repr(C)]
pub struct DpBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl DpBuf {
    const EMPTY: DpBuf = DpBuf {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };

    fn from_vec(mut v: Vec<u8>) -> DpBuf {
        let out = DpBuf {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        out
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

/// Wrap a fallible body so neither a panic nor an error escapes as anything but
/// a status code, and so the message survives until the caller asks for it.
fn guard<F: FnOnce() -> Result<i32, String>>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(code)) => code,
        Ok(Err(msg)) => {
            let code = if msg.contains(gate::NOT_APPROVED) {
                DPMLS_ERR_UNTRUSTED
            } else {
                DPMLS_ERR
            };
            set_error(msg);
            code
        }
        Err(_) => {
            set_error("mls: panic crossed the C ABI boundary");
            DPMLS_ERR_PANIC
        }
    }
}

/// # Safety
/// `ptr` must be null, or point to `len` readable bytes that stay valid for the
/// duration of the call.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("mls: null pointer with a non-zero length".into());
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

unsafe fn session_of<'a>(handle: *mut Session) -> Result<&'a mut Session, String> {
    handle
        .as_mut()
        .ok_or_else(|| "mls: null session handle".into())
}

unsafe fn put(out: *mut DpBuf, v: Vec<u8>) -> Result<(), String> {
    if out.is_null() {
        return Err("mls: null output buffer".into());
    }
    *out = DpBuf::from_vec(v);
    Ok(())
}

// ─── library identity ───────────────────────────────────────────────────

/// Versions of the crates actually linked in, plus the two features whose
/// absence would only show up much later. Go asserts on this string so that a
/// build assembled without them fails a test rather than a send.
///
/// # Safety
/// `out` must point to a writable DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_version(out: *mut DpBuf) -> i32 {
    guard(|| {
        let s = format!(
            "mls-rs {} / mls-rs-crypto-rustcrypto {} / features={} / ciphersuite={}",
            "0.56.0",
            "0.22.1",
            "secret_tree_access,export_key_generation",
            u16::from(session::CIPHER_SUITE),
        );
        unsafe { put(out, s.into_bytes())? };
        Ok(DPMLS_OK)
    })
}

/// Copy out the last error this thread produced. Empty when there is none.
///
/// # Safety
/// `out` must point to a writable DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_last_error(out: *mut DpBuf) -> i32 {
    guard(|| {
        let msg = LAST_ERROR.with(|e| e.borrow().clone());
        unsafe { put(out, msg.into_bytes())? };
        Ok(DPMLS_OK)
    })
}

/// Release a buffer this library returned, wiping it first.
///
/// # Safety
/// `buf` must be a DpBuf this library filled and nothing else has freed.
#[no_mangle]
pub unsafe extern "C" fn dpmls_buf_free(buf: *mut DpBuf) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(b) = buf.as_mut() else { return };
        if b.ptr.is_null() {
            return;
        }
        let mut v = Vec::from_raw_parts(b.ptr, b.len, b.cap);
        v.zeroize();
        drop(v);
        *b = DpBuf::EMPTY;
    }));
}

// ─── keys and sessions ──────────────────────────────────────────────────

/// Generate a signature keypair for this device's leaf.
///
/// Where that key lives between calls is not decided here — custody belongs to
/// Keeper's keychain layer. This exists so the skeleton can stand up a group
/// without inventing a custody answer it would then have to unpick.
///
/// # Safety
/// Both arguments must point to writable DpBufs.
#[no_mangle]
pub unsafe extern "C" fn dpmls_signature_key_generate(
    secret: *mut DpBuf,
    public: *mut DpBuf,
) -> i32 {
    guard(|| {
        let (sk, pk) = session::generate_signature_key()?;
        unsafe {
            put(secret, sk)?;
            put(public, pk)?;
        }
        Ok(DPMLS_OK)
    })
}

/// `declaration` is the payload of this device's leaf declaration extension,
/// carried in every leaf the session creates. Empty means the leaf carries
/// none, which only a test member does: every peer refuses such a leaf.
///
/// # Safety
/// The four input pointers follow the rules in `slice`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn dpmls_session_new(
    identity: *const u8,
    identity_len: usize,
    secret: *const u8,
    secret_len: usize,
    public: *const u8,
    public_len: usize,
    declaration: *const u8,
    declaration_len: usize,
    out: *mut *mut Session,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let s = Session::new(
            slice(identity, identity_len)?,
            slice(secret, secret_len)?,
            slice(public, public_len)?,
            slice(declaration, declaration_len)?,
        )?;
        *out = Box::into_raw(Box::new(s));
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// `handle` must come from `dpmls_session_new` and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn dpmls_session_free(handle: *mut Session) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    }));
}

// ─── group lifecycle ────────────────────────────────────────────────────

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_create(
    handle: *mut Session,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        session_of(handle)?.create_group(slice(group_id, group_id_len)?)?;
        Ok(DPMLS_OK)
    })
}

/// One KeyPackage ending no later than `not_after_cap` (Unix seconds).
/// `message` receives the KeyPackage, `reference` its KeyPackage reference and
/// `private` the entry holding its two private keys, which the caller must
/// persist before handing out the message and must pass back through
/// `dpmls_session_install_key_package` to join a Welcome addressed to it.
/// Nothing of the private keys stays in the session.
///
/// # Safety
/// `handle` as in `session_of`; the three outputs must point to writable
/// DpBufs.
#[no_mangle]
pub unsafe extern "C" fn dpmls_key_package(
    handle: *mut Session,
    not_after_cap: u64,
    message: *mut DpBuf,
    reference: *mut DpBuf,
    private: *mut DpBuf,
) -> i32 {
    guard(|| {
        if message.is_null() || reference.is_null() || private.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently; the borrow ends with this statement.
        let mut generated = unsafe { session_of(handle)? }.key_package(not_after_cap)?;
        // SAFETY: the three outputs were checked for null above and the caller
        // promises each points to a writable DpBuf; `put` overwrites them
        // without reading them. The private entry moves into a DpBuf, which
        // dpmls_buf_free wipes before releasing.
        unsafe {
            put(message, generated.message)?;
            put(reference, generated.reference)?;
            put(private, std::mem::take(&mut *generated.private))?;
        }
        Ok(DPMLS_OK)
    })
}

/// Hand the session the private entry of the KeyPackage a Welcome is addressed
/// to, for the next join only. The join drops it whether it succeeds or not.
///
/// # Safety
/// `handle` as in `session_of`; `entry` follows the rules in `slice`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_session_install_key_package(
    handle: *mut Session,
    entry: *const u8,
    entry_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently, and that `entry` points to `entry_len`
        // readable bytes for the duration of this call. The bytes are decoded
        // into owned values before the call returns.
        let (session, entry) = unsafe { (session_of(handle)?, slice(entry, entry_len)?) };
        session.install_key_package(entry)?;
        Ok(DPMLS_OK)
    })
}

/// The KeyPackage references a Welcome is addressed to, framed as a u32 count
/// followed by each reference u32-length-prefixed, big-endian.
///
/// # Safety
/// `welcome` follows the rules in `slice`; `out` must point to a writable
/// DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_welcome_key_package_refs(
    welcome: *const u8,
    welcome_len: usize,
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `welcome` points to `welcome_len`
        // readable bytes for the duration of this call; the borrow ends before
        // this block does.
        let refs = session::welcome_key_package_refs(unsafe { slice(welcome, welcome_len)? })?;
        let count =
            u32::try_from(refs.len()).map_err(|_| "mls: too many references".to_string())?;
        let mut framed = Vec::new();
        framed.extend_from_slice(&count.to_be_bytes());
        for r in &refs {
            let len = u32::try_from(r.len()).map_err(|_| "mls: reference too long".to_string())?;
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(r);
        }
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, framed)? };
        Ok(DPMLS_OK)
    })
}

/// Set the leaves the Go side verified for the next group operation on this
/// session: the next process, join or Add build. That operation consumes the
/// list whether it succeeds or not.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_session_approve(
    handle: *mut Session,
    approvals: *const u8,
    approvals_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently, and that `approvals` points to
        // `approvals_len` readable bytes for the duration of this call. The
        // bytes are decoded into owned values before the call returns.
        let (session, buf) = unsafe { (session_of(handle)?, slice(approvals, approvals_len)?) };
        let approved = gate::decode_approvals(buf).map_err(|e| format!("mls: {e}"))?;
        session.approve(approved);
        Ok(DPMLS_OK)
    })
}

/// Read the leaf a KeyPackage would add, without a session. `out` receives it
/// in the leaf framing of `gate::encode_leaves`, as a list of one.
///
/// # Safety
/// Pointer rules as in `slice`; `out` must point to a writable DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_key_package_leaf(
    key_package: *const u8,
    key_package_len: usize,
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `key_package` points to
        // `key_package_len` readable bytes for the duration of this call; the
        // borrow ends before this block does.
        let leaf = session::key_package_leaf(unsafe { slice(key_package, key_package_len)? })?;
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, gate::encode_leaves(&[leaf]))? };
        Ok(DPMLS_OK)
    })
}

/// The `not_after` of a KeyPackage's lifetime, in Unix seconds.
///
/// # Safety
/// Pointer rules as in `slice`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn dpmls_key_package_not_after(
    key_package: *const u8,
    key_package_len: usize,
    out: *mut u64,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        // SAFETY: the caller promises `key_package` points to
        // `key_package_len` readable bytes for the duration of this call; the
        // borrow ends before this block does.
        let not_after =
            session::key_package_not_after(unsafe { slice(key_package, key_package_len)? })?;
        // SAFETY: `out` was checked for null above and the caller promises it
        // points to a writable u64.
        unsafe { *out = not_after };
        Ok(DPMLS_OK)
    })
}

/// The collect pass of processing: report the leaves `message` would bring
/// in, leaving the group exactly as it was.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_process_collect(
    handle: *mut Session,
    message: *const u8,
    message_len: usize,
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently, and that `message` points to `message_len`
        // readable bytes for the duration of this call.
        let (session, msg) = unsafe { (session_of(handle)?, slice(message, message_len)?) };
        let leaves = session.process_collect(msg)?;
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, gate::encode_leaves(&leaves))? };
        Ok(DPMLS_OK)
    })
}

/// The collect pass of a join: report every leaf of the Welcome's tree and
/// keep no group.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_join_collect(
    handle: *mut Session,
    welcome: *const u8,
    welcome_len: usize,
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently, and that `welcome` points to `welcome_len`
        // readable bytes for the duration of this call.
        let (session, msg) = unsafe { (session_of(handle)?, slice(welcome, welcome_len)?) };
        let leaves = session.join_collect(msg)?;
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, gate::encode_leaves(&leaves))? };
        Ok(DPMLS_OK)
    })
}

/// Build an Add Commit for one or more members and hold it pending.
/// `key_packages` is framed as in `gate::decode_key_packages`.
/// `expected_epoch` receives the confirmed epoch the Commit was built against,
/// which is what the server compares under its CAS. Nothing in the group moves
/// until `dpmls_group_commit_apply`.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_commit_add_members(
    handle: *mut Session,
    key_packages: *const u8,
    key_packages_len: usize,
    commit: *mut DpBuf,
    welcome: *mut DpBuf,
    expected_epoch: *mut u64,
) -> i32 {
    guard(|| {
        if expected_epoch.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let framed = slice(key_packages, key_packages_len)?;
        let kps = gate::decode_key_packages(framed).map_err(|e| format!("mls: {e}"))?;
        let (c, w, epoch) = session_of(handle)?.commit_add_members(&kps)?;
        *expected_epoch = epoch;
        put(commit, c)?;
        put(welcome, w)?;
        Ok(DPMLS_OK)
    })
}

/// Build a Commit with no proposals and hold it pending.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_commit_update(
    handle: *mut Session,
    commit: *mut DpBuf,
    expected_epoch: *mut u64,
) -> i32 {
    guard(|| {
        if expected_epoch.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let (c, epoch) = session_of(handle)?.commit_update()?;
        *expected_epoch = epoch;
        put(commit, c)?;
        Ok(DPMLS_OK)
    })
}

/// Build a Commit that removes the leaves in `leaf_indices` (framed as in
/// `gate::decode_leaf_indices`) and hold it pending. `expected_epoch` receives
/// the confirmed epoch it was built against.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`; `commit` must
/// point to a writable DpBuf and `expected_epoch` to a writable u64.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_commit_remove_members(
    handle: *mut Session,
    leaf_indices: *const u8,
    leaf_indices_len: usize,
    commit: *mut DpBuf,
    expected_epoch: *mut u64,
) -> i32 {
    guard(|| {
        if expected_epoch.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently, and that `leaf_indices` points to
        // `leaf_indices_len` readable bytes for the duration of this call. The
        // indices are decoded into an owned Vec before the borrow ends.
        let (session, framed) =
            unsafe { (session_of(handle)?, slice(leaf_indices, leaf_indices_len)?) };
        let indices = gate::decode_leaf_indices(framed).map_err(|e| format!("mls: {e}"))?;
        let (c, epoch) = session.commit_remove_members(&indices)?;
        // SAFETY: `expected_epoch` was checked for null above and the caller
        // promises it points to a writable u64; the caller promises `commit`
        // points to a writable DpBuf, which `put` checks for null and
        // overwrites without reading.
        unsafe {
            *expected_epoch = epoch;
            put(commit, c)?;
        }
        Ok(DPMLS_OK)
    })
}

/// Every leaf of the confirmed tree, never one only a pending Commit reaches,
/// in the leaf framing of `gate::encode_leaves`.
///
/// # Safety
/// `handle` as in `session_of`; `out` must point to a writable DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_roster(handle: *mut Session, out: *mut DpBuf) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently; the borrow ends with this statement.
        let leaves = unsafe { session_of(handle)? }.roster()?;
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, gate::encode_leaves(&leaves))? };
        Ok(DPMLS_OK)
    })
}

/// The group's id, which this integration sets to the conversation id when it
/// creates the group. A joiner compares the two before it keeps a group a
/// Welcome produced.
///
/// # Safety
/// `handle` as in `session_of`; `out` must point to a writable DpBuf.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_id(handle: *mut Session, out: *mut DpBuf) -> i32 {
    guard(|| {
        // SAFETY: the caller promises `handle` came from dpmls_session_new and
        // is not used concurrently; the borrow ends with this statement.
        let id = unsafe { session_of(handle)? }.group_id()?;
        // SAFETY: the caller promises `out` points to a writable DpBuf; `put`
        // checks it for null and overwrites it without reading it.
        unsafe { put(out, id)? };
        Ok(DPMLS_OK)
    })
}

/// Promote the pending Commit to confirmed.
///
/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_commit_apply(handle: *mut Session) -> i32 {
    guard(|| {
        session_of(handle)?.apply_pending_commit()?;
        Ok(DPMLS_OK)
    })
}

/// Drop the pending Commit along with the next-epoch secrets it carries.
///
/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_commit_clear(handle: *mut Session) -> i32 {
    guard(|| {
        session_of(handle)?.clear_pending_commit()?;
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// `handle` as in `session_of`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_has_pending_commit(handle: *mut Session, out: *mut u8) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        *out = u8::from(session_of(handle)?.has_pending_commit()?);
        Ok(DPMLS_OK)
    })
}

/// The confirmed epoch, never one that only a pending Commit would reach.
///
/// # Safety
/// `handle` as in `session_of`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_epoch(handle: *mut Session, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        *out = session_of(handle)?.epoch()?;
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_join(
    handle: *mut Session,
    welcome: *const u8,
    welcome_len: usize,
) -> i32 {
    guard(|| {
        session_of(handle)?.join(slice(welcome, welcome_len)?)?;
        Ok(DPMLS_OK)
    })
}

// ─── messages ───────────────────────────────────────────────────────────

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_encrypt(
    handle: *mut Session,
    plaintext: *const u8,
    plaintext_len: usize,
    authenticated_data: *const u8,
    authenticated_data_len: usize,
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        let ct = session_of(handle)?.encrypt(
            slice(plaintext, plaintext_len)?,
            slice(authenticated_data, authenticated_data_len)?,
        )?;
        put(out, ct)?;
        Ok(DPMLS_OK)
    })
}

/// Apply one inbound message. `out` receives the plaintext for an application
/// message and stays empty for everything else.
///
/// `key_generation` is only meaningful when `key_generation_known` is 1. The
/// two are separate outputs rather than one sentinel value because the library
/// answers `None` when it could not extract the generation, and a caller that
/// folded that into 0 would compare a declared 0 against an unknown and call it
/// a match.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn dpmls_group_process(
    handle: *mut Session,
    message: *const u8,
    message_len: usize,
    out: *mut DpBuf,
    authenticated_data: *mut DpBuf,
    epoch: *mut u64,
    sender_index: *mut u32,
    removed: *mut u8,
    is_application: *mut u8,
    key_generation: *mut u32,
    key_generation_known: *mut u8,
) -> i32 {
    guard(|| {
        if epoch.is_null()
            || sender_index.is_null()
            || removed.is_null()
            || is_application.is_null()
            || key_generation.is_null()
            || key_generation_known.is_null()
        {
            return Ok(DPMLS_ERR_ARG);
        }
        let Processed {
            epoch: e,
            removed: r,
            application,
            sender_index: leaf,
            authenticated_data: aad,
            key_generation: gen,
        } = session_of(handle)?.process(slice(message, message_len)?)?;
        *epoch = e;
        *sender_index = leaf;
        *removed = u8::from(r);
        *is_application = u8::from(application.is_some());
        *key_generation = gen.unwrap_or(0);
        *key_generation_known = u8::from(gen.is_some());
        put(authenticated_data, aad)?;
        put(out, take_zeroizing(application))?;
        Ok(DPMLS_OK)
    })
}

/// Read the plaintext out of its Zeroizing wrapper into the Vec that becomes
/// the returned buffer. The wrapper's copy is wiped on drop; the returned one
/// is wiped by dpmls_buf_free. Between the two the plaintext exists twice.
fn take_zeroizing(v: Option<Zeroizing<Vec<u8>>>) -> Vec<u8> {
    match v {
        Some(z) => z.to_vec(),
        None => Vec::new(),
    }
}

/// Classify encoded bytes by the wire format recorded in them.
///
/// # Safety
/// Pointer rules as in `slice`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_wire_form(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let form: WireForm = session::wire_form(slice(message, message_len)?)?;
        *out = form as u8;
        Ok(DPMLS_OK)
    })
}

// ─── state ──────────────────────────────────────────────────────────────

/// Read the send chain position without advancing it.
///
/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_send_position(
    handle: *mut Session,
    epoch: *mut u64,
    leaf_index: *mut u32,
    generation: *mut u32,
) -> i32 {
    guard(|| {
        if epoch.is_null() || leaf_index.is_null() || generation.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let (e, leaf, gen) = session_of(handle)?.send_position()?;
        *epoch = e;
        *leaf_index = leaf;
        *generation = gen;
        Ok(DPMLS_OK)
    })
}

/// Consume one application generation without producing a ciphertext. The
/// derived key never crosses this boundary.
///
/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_burn_generation(handle: *mut Session) -> i32 {
    guard(|| {
        session_of(handle)?.burn_generation()?;
        Ok(DPMLS_OK)
    })
}

/// Serialize the group so the caller can persist it.
///
/// The bytes come out of the GroupStateStorage this session installed, because
/// mls-rs keeps Snapshot and Group::snapshot() crate-private: the only way to
/// hold the serialized state is to be handed it by a write. Durability is the
/// caller's from here on.
///
/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_flush(handle: *mut Session, out: *mut DpBuf) -> i32 {
    guard(|| {
        let blob = session_of(handle)?.flush()?;
        put(out, blob.to_vec())?;
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_load(
    handle: *mut Session,
    blob: *const u8,
    blob_len: usize,
) -> i32 {
    guard(|| {
        session_of(handle)?.load(slice(blob, blob_len)?)?;
        Ok(DPMLS_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(buf: &mut DpBuf) -> Vec<u8> {
        let out = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec();
        unsafe { dpmls_buf_free(buf) };
        out
    }

    #[test]
    fn version_names_the_two_features_that_are_off_by_default() {
        let mut buf = DpBuf::EMPTY;
        assert_eq!(unsafe { dpmls_version(&mut buf) }, DPMLS_OK);
        let s = String::from_utf8(take(&mut buf)).unwrap();
        assert!(s.contains("secret_tree_access"), "{s}");
        assert!(s.contains("export_key_generation"), "{s}");
    }

    // A freed buffer is left null, so a caller that frees twice — which an
    // error path combined with a deferred free would do — releases once.
    #[test]
    fn freeing_a_buffer_twice_is_harmless() {
        let mut buf = DpBuf::EMPTY;
        assert_eq!(unsafe { dpmls_version(&mut buf) }, DPMLS_OK);
        assert!(!buf.ptr.is_null());
        unsafe { dpmls_buf_free(&mut buf) };
        assert!(buf.ptr.is_null());
        unsafe { dpmls_buf_free(&mut buf) };
        unsafe { dpmls_buf_free(std::ptr::null_mut()) };
    }

    #[test]
    fn a_null_handle_is_an_error_rather_than_a_dereference() {
        assert_eq!(
            unsafe { dpmls_group_create(std::ptr::null_mut(), b"gid".as_ptr(), 3) },
            DPMLS_ERR
        );
        let mut buf = DpBuf::EMPTY;
        assert_eq!(unsafe { dpmls_last_error(&mut buf) }, DPMLS_OK);
        assert!(String::from_utf8(take(&mut buf))
            .unwrap()
            .contains("null session handle"));
    }

    #[test]
    fn a_null_input_with_a_length_is_refused() {
        assert_eq!(
            unsafe { dpmls_group_create(std::ptr::null_mut(), std::ptr::null(), 7) },
            DPMLS_ERR
        );
    }
}
