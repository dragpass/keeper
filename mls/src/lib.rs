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
            set_error(msg);
            DPMLS_ERR
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

/// # Safety
/// The three input pointers follow the rules in `slice`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_session_new(
    identity: *const u8,
    identity_len: usize,
    secret: *const u8,
    secret_len: usize,
    public: *const u8,
    public_len: usize,
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

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_key_package(handle: *mut Session, out: *mut DpBuf) -> i32 {
    guard(|| {
        let kp = session_of(handle)?.key_package()?;
        put(out, kp)?;
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_add_member(
    handle: *mut Session,
    key_package: *const u8,
    key_package_len: usize,
    commit: *mut DpBuf,
    welcome: *mut DpBuf,
) -> i32 {
    guard(|| {
        let (c, w) = session_of(handle)?.add_member(slice(key_package, key_package_len)?)?;
        put(commit, c)?;
        put(welcome, w)?;
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
    out: *mut DpBuf,
) -> i32 {
    guard(|| {
        let ct = session_of(handle)?.encrypt(slice(plaintext, plaintext_len)?)?;
        put(out, ct)?;
        Ok(DPMLS_OK)
    })
}

/// Apply one inbound message. `out` receives the plaintext for an application
/// message and stays empty for everything else.
///
/// # Safety
/// Pointer rules as in `slice`; `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_process(
    handle: *mut Session,
    message: *const u8,
    message_len: usize,
    out: *mut DpBuf,
    epoch: *mut u64,
    removed: *mut u8,
    is_application: *mut u8,
) -> i32 {
    guard(|| {
        let Processed {
            epoch: e,
            removed: r,
            application,
        } = session_of(handle)?.process(slice(message, message_len)?)?;
        if epoch.is_null() || removed.is_null() || is_application.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        *epoch = e;
        *removed = u8::from(r);
        *is_application = u8::from(application.is_some());
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

/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_peek_generation(handle: *mut Session, out: *mut u32) -> i32 {
    guard(|| {
        if out.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        *out = session_of(handle)?.peek_generation()?;
        Ok(DPMLS_OK)
    })
}

/// # Safety
/// `handle` as in `session_of`.
#[no_mangle]
pub unsafe extern "C" fn dpmls_group_epoch(
    handle: *mut Session,
    epoch: *mut u64,
    member_index: *mut u32,
) -> i32 {
    guard(|| {
        if epoch.is_null() || member_index.is_null() {
            return Ok(DPMLS_ERR_ARG);
        }
        let s = session_of(handle)?;
        *epoch = s.epoch()?;
        *member_index = s.member_index()?;
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
