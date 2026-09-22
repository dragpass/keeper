//go:build mls && cgo

// bridge_cgo.go — the cgo binding onto the Rust static library in ../../../mls.
//
// # Why cgo and a static library rather than a second process
//
// A sidecar would have kept Linux on CGO_ENABLED=0, and that is a real cost
// this choice pays. Three things ruled it out anyway. The serialized group
// state would have to cross a process boundary in both directions, which is the
// one thing the architecture says it never does. The ordering discipline the
// next step builds needs the conversation lock, the encryption, and the write
// to sit in one critical section; split across processes that becomes a
// distributed transaction over a pipe. And the secret-handling surface would
// double rather than move. In-process linking keeps all three in the place that
// already owns them.
//
// # Buffer ownership
//
//   - Out: Rust allocates, Go copies with C.GoBytes, Go returns the buffer with
//     dpmls_buf_free, which zeroes it before releasing. Every path that can
//     reach a buffer frees it, including the error paths.
//   - In: Go passes a pointer into its own slice, valid for the call only. The
//     Rust side copies and keeps nothing, which is what cgo's pointer rules
//     require. Wiping those is the caller's job.
//
// zeroize on the Rust side covers the buffer being dropped and nothing else:
// not intermediate copies, not a reallocated Vec's abandoned block, not swap,
// not a core dump.

package mls

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../mls/target/release -ldragpass_mls
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#cgo linux LDFLAGS: -lm -ldl -pthread
#cgo windows LDFLAGS: -lbcrypt -lntdll -luserenv -lws2_32

#include <stdint.h>
#include <stdlib.h>

typedef struct { uint8_t *ptr; size_t len; size_t cap; } DpBuf;
typedef struct DpSession DpSession;

int32_t dpmls_version(DpBuf *out);
int32_t dpmls_last_error(DpBuf *out);
void    dpmls_buf_free(DpBuf *buf);

int32_t dpmls_signature_key_generate(DpBuf *secret, DpBuf *public);
int32_t dpmls_session_new(const uint8_t *identity, size_t identity_len,
                          const uint8_t *secret, size_t secret_len,
                          const uint8_t *public, size_t public_len,
                          DpSession **out);
void    dpmls_session_free(DpSession *handle);

int32_t dpmls_group_create(DpSession *handle, const uint8_t *group_id, size_t group_id_len);
int32_t dpmls_key_package(DpSession *handle, DpBuf *out);
int32_t dpmls_group_add_member(DpSession *handle,
                               const uint8_t *key_package, size_t key_package_len,
                               DpBuf *commit, DpBuf *welcome);
int32_t dpmls_group_join(DpSession *handle, const uint8_t *welcome, size_t welcome_len);

int32_t dpmls_group_encrypt(DpSession *handle,
                            const uint8_t *plaintext, size_t plaintext_len, DpBuf *out);
int32_t dpmls_group_process(DpSession *handle,
                            const uint8_t *message, size_t message_len,
                            DpBuf *out, uint64_t *epoch,
                            uint8_t *removed, uint8_t *is_application);
int32_t dpmls_wire_form(const uint8_t *message, size_t message_len, uint8_t *out);

int32_t dpmls_group_peek_generation(DpSession *handle, uint32_t *out);
int32_t dpmls_group_epoch(DpSession *handle, uint64_t *epoch, uint32_t *member_index);
int32_t dpmls_group_flush(DpSession *handle, DpBuf *out);
int32_t dpmls_group_load(DpSession *handle, const uint8_t *blob, size_t blob_len);
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Session is one conversation's MLS client and group.
//
// The mutex is not about concurrent users. It is about the pointer: a closed
// session must not be reachable through a second call, and the library's own
// warning that peeking a generation "is only safe for synchronous usage" means
// two calls must never interleave on one handle.
type Session struct {
	mu     sync.Mutex
	handle *C.DpSession
}

func Available() bool { return true }

func Version() (string, error) {
	var buf C.DpBuf
	if rc := C.dpmls_version(&buf); rc != 0 {
		return "", statusError(rc)
	}
	return string(takeBuf(&buf)), nil
}

func GenerateSignatureKey() (secret, public []byte, err error) {
	var sk, pk C.DpBuf
	if rc := C.dpmls_signature_key_generate(&sk, &pk); rc != 0 {
		return nil, nil, statusError(rc)
	}
	return takeBuf(&sk), takeBuf(&pk), nil
}

// NewSession builds a client for one device identity. The caller owns the key
// material it passes and should wipe it afterwards; this package copies it
// across the boundary and cannot reach the caller's copy again.
func NewSession(identity, secretKey, publicKey []byte) (*Session, error) {
	var handle *C.DpSession
	rc := C.dpmls_session_new(
		bytePtr(identity), C.size_t(len(identity)),
		bytePtr(secretKey), C.size_t(len(secretKey)),
		bytePtr(publicKey), C.size_t(len(publicKey)),
		&handle,
	)
	runtime.KeepAlive(identity)
	runtime.KeepAlive(secretKey)
	runtime.KeepAlive(publicKey)
	if rc != 0 {
		return nil, statusError(rc)
	}
	return &Session{handle: handle}, nil
}

// Close releases the Rust session. Calling it twice is safe and calling
// anything else after it fails rather than dereferencing a freed pointer.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		C.dpmls_session_free(s.handle)
		s.handle = nil
	}
}

var errClosed = errors.New("mls: session is closed")

func (s *Session) live() (*C.DpSession, error) {
	if s.handle == nil {
		return nil, errClosed
	}
	return s.handle, nil
}

func (s *Session) CreateGroup(groupID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	rc := C.dpmls_group_create(h, bytePtr(groupID), C.size_t(len(groupID)))
	runtime.KeepAlive(groupID)
	return statusError(rc)
}

func (s *Session) KeyPackage() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	if rc := C.dpmls_key_package(h, &buf); rc != 0 {
		return nil, statusError(rc)
	}
	return takeBuf(&buf), nil
}

func (s *Session) AddMember(keyPackage []byte) (commit, welcome []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, nil, err
	}
	var c, w C.DpBuf
	rc := C.dpmls_group_add_member(h, bytePtr(keyPackage), C.size_t(len(keyPackage)), &c, &w)
	runtime.KeepAlive(keyPackage)
	if rc != 0 {
		return nil, nil, statusError(rc)
	}
	return takeBuf(&c), takeBuf(&w), nil
}

func (s *Session) Join(welcome []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	rc := C.dpmls_group_join(h, bytePtr(welcome), C.size_t(len(welcome)))
	runtime.KeepAlive(welcome)
	return statusError(rc)
}

func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	rc := C.dpmls_group_encrypt(h, bytePtr(plaintext), C.size_t(len(plaintext)), &buf)
	runtime.KeepAlive(plaintext)
	if rc != 0 {
		return nil, statusError(rc)
	}
	return takeBuf(&buf), nil
}

func (s *Session) Process(message []byte) (Processed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return Processed{}, err
	}
	var (
		buf           C.DpBuf
		epoch         C.uint64_t
		removed       C.uint8_t
		isApplication C.uint8_t
	)
	rc := C.dpmls_group_process(
		h, bytePtr(message), C.size_t(len(message)),
		&buf, &epoch, &removed, &isApplication,
	)
	runtime.KeepAlive(message)
	if rc != 0 {
		return Processed{}, statusError(rc)
	}
	return Processed{
		Epoch:       uint64(epoch),
		Removed:     removed != 0,
		Application: isApplication != 0,
		Plaintext:   takeBuf(&buf),
	}, nil
}

func WireFormOf(message []byte) (WireForm, error) {
	var form C.uint8_t
	rc := C.dpmls_wire_form(bytePtr(message), C.size_t(len(message)), &form)
	runtime.KeepAlive(message)
	if rc != 0 {
		return WireFormOther, statusError(rc)
	}
	return WireForm(form), nil
}

// PeekGeneration reports the next application generation this device would
// consume, without consuming it. Two things about it matter to the caller:
// it compiles only in a build carrying both export_key_generation and
// secret_tree_access, and it is a read rather than a claim, so whatever holds
// the conversation lock has to span from here to the encryption that takes the
// number.
func (s *Session) PeekGeneration() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return 0, err
	}
	var out C.uint32_t
	if rc := C.dpmls_group_peek_generation(h, &out); rc != 0 {
		return 0, statusError(rc)
	}
	return uint32(out), nil
}

func (s *Session) Epoch() (epoch uint64, memberIndex uint32, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return 0, 0, err
	}
	var e C.uint64_t
	var idx C.uint32_t
	if rc := C.dpmls_group_epoch(h, &e, &idx); rc != 0 {
		return 0, 0, statusError(rc)
	}
	return uint64(e), uint32(idx), nil
}

// Flush serializes the group and hands back the bytes to persist.
//
// The bytes come out of the GroupStateStorage the session installed, because
// mls-rs keeps its Snapshot type crate-private: being handed the state by a
// write is the only way to hold it. Nothing is durable until the caller stores
// what this returns.
func (s *Session) Flush() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	if rc := C.dpmls_group_flush(h, &buf); rc != 0 {
		return nil, statusError(rc)
	}
	return takeBuf(&buf), nil
}

func (s *Session) Load(blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	rc := C.dpmls_group_load(h, bytePtr(blob), C.size_t(len(blob)))
	runtime.KeepAlive(blob)
	return statusError(rc)
}

// ────────────────────────────────────────────────────────────────────────

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// takeBuf copies a Rust-owned buffer into Go memory and gives the original
// back to be wiped and freed. Every caller runs this, including on the paths
// where the value is discarded, because the free is what does the wiping.
func takeBuf(buf *C.DpBuf) []byte {
	defer C.dpmls_buf_free(buf)
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

func statusError(rc C.int32_t) error {
	if rc == 0 {
		return nil
	}
	var buf C.DpBuf
	msg := ""
	if C.dpmls_last_error(&buf) == 0 {
		msg = string(takeBuf(&buf))
	}
	if msg == "" {
		msg = "unknown failure"
	}
	return fmt.Errorf("mls (status %d): %s", int(rc), msg)
}
