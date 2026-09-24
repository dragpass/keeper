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
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../mls/target/release -ldragpass_mls -framework CoreFoundation -framework Security
#cgo linux LDFLAGS: -L${SRCDIR}/../../../mls/target/release -ldragpass_mls -lm -ldl -pthread
// Windows names the triple because the release is mingw, never MSVC, while a
// Windows host's default cargo target is MSVC — so "target/release" there holds
// an archive this linker cannot use. Cross-building from another host adds its
// own -L through CGO_LDFLAGS.
#cgo windows LDFLAGS: -L${SRCDIR}/../../../mls/target/x86_64-pc-windows-gnu/release -ldragpass_mls -lbcrypt -lntdll -luserenv -lws2_32

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
                          const uint8_t *declaration, size_t declaration_len,
                          DpSession **out);
void    dpmls_session_free(DpSession *handle);
int32_t dpmls_session_approve(DpSession *handle, const uint8_t *approvals, size_t approvals_len);
int32_t dpmls_session_approve_removals(DpSession *handle, const uint8_t *removals, size_t removals_len);
int32_t dpmls_key_package_leaf(const uint8_t *key_package, size_t key_package_len, DpBuf *out);
int32_t dpmls_key_package_not_after(const uint8_t *key_package, size_t key_package_len, uint64_t *out);
int32_t dpmls_group_process_collect(DpSession *handle, const uint8_t *message, size_t message_len, DpBuf *out);
int32_t dpmls_group_join_collect(DpSession *handle, const uint8_t *welcome, size_t welcome_len, DpBuf *out);

int32_t dpmls_group_create(DpSession *handle, const uint8_t *group_id, size_t group_id_len);
int32_t dpmls_key_package(DpSession *handle, uint64_t not_after_cap,
                          DpBuf *message, DpBuf *reference, DpBuf *private_entry);
int32_t dpmls_session_install_key_package(DpSession *handle, const uint8_t *entry, size_t entry_len);
int32_t dpmls_welcome_key_package_refs(const uint8_t *welcome, size_t welcome_len, DpBuf *out);
int32_t dpmls_group_commit_add_members(DpSession *handle,
                                       const uint8_t *key_packages, size_t key_packages_len,
                                       DpBuf *commit, DpBuf *welcome, uint64_t *expected_epoch);
int32_t dpmls_group_commit_update(DpSession *handle, DpBuf *commit, uint64_t *expected_epoch);
int32_t dpmls_group_commit_remove_members(DpSession *handle,
                                          const uint8_t *leaf_indices, size_t leaf_indices_len,
                                          DpBuf *commit, uint64_t *expected_epoch);
int32_t dpmls_group_commit_replace_members(DpSession *handle,
                                           const uint8_t *leaf_indices, size_t leaf_indices_len,
                                           const uint8_t *key_packages, size_t key_packages_len,
                                           DpBuf *commit, DpBuf *welcome, uint64_t *expected_epoch);
int32_t dpmls_group_roster(DpSession *handle, DpBuf *out);
int32_t dpmls_group_commit_apply(DpSession *handle);
int32_t dpmls_group_commit_clear(DpSession *handle);
int32_t dpmls_group_has_pending_commit(DpSession *handle, uint8_t *out);
int32_t dpmls_group_epoch(DpSession *handle, uint64_t *out);
int32_t dpmls_group_id(DpSession *handle, DpBuf *out);
int32_t dpmls_group_join(DpSession *handle, const uint8_t *welcome, size_t welcome_len);

int32_t dpmls_group_encrypt(DpSession *handle,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *authenticated_data, size_t authenticated_data_len,
                            DpBuf *out);
int32_t dpmls_group_process(DpSession *handle,
                            const uint8_t *message, size_t message_len,
                            DpBuf *out, DpBuf *authenticated_data,
                            uint64_t *epoch, uint32_t *sender_index,
                            uint8_t *removed, uint8_t *is_application,
                            uint32_t *key_generation, uint8_t *key_generation_known);
int32_t dpmls_wire_form(const uint8_t *message, size_t message_len, uint8_t *out);

int32_t dpmls_group_export_secret(DpSession *handle,
                                  const uint8_t *label, size_t label_len,
                                  const uint8_t *context, size_t context_len,
                                  size_t len, DpBuf *out);
int32_t dpmls_group_export_pending_secret(DpSession *handle,
                                          const uint8_t *label, size_t label_len,
                                          const uint8_t *context, size_t context_len,
                                          size_t len, uint64_t *epoch, DpBuf *out);

int32_t dpmls_group_send_position(DpSession *handle,
                                  uint64_t *epoch, uint32_t *leaf_index, uint32_t *generation);
int32_t dpmls_group_burn_generation(DpSession *handle);
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

	"github.com/dragpass/keeper/internal/keystore/chatstate"
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

	// leafFingerprint is the active leaf NewDeviceSession opened this session
	// as. Empty for a session built any other way.
	leafFingerprint string
}

func Available() bool { return true }

func Version() (string, error) {
	var buf C.DpBuf
	if rc := C.dpmls_version(&buf); rc != 0 {
		return "", statusError(rc)
	}
	return string(takeBuf(&buf)), nil
}

// generateSignatureKey is for tests that need a throwaway member. A real
// session signs with the device's declared key, which NewDeviceSession loads.
func generateSignatureKey() (secret, public []byte, err error) {
	var sk, pk C.DpBuf
	if rc := C.dpmls_signature_key_generate(&sk, &pk); rc != 0 {
		return nil, nil, statusError(rc)
	}
	return takeBuf(&sk), takeBuf(&pk), nil
}

// openSession builds a client for one device identity. The caller owns the key
// material it passes and should wipe it afterwards; this package copies it
// across the boundary and cannot reach the caller's copy again. declaration is
// the leaf declaration extension payload every leaf of this session carries;
// empty means none, which every verifying peer refuses.
//
// Unexported so that no caller can hand a group a signer of its own: a key no
// declaration vouches for would make the leaf unacceptable to every peer.
func openSession(identity, secretKey, publicKey, declaration []byte) (*Session, error) {
	var handle *C.DpSession
	rc := C.dpmls_session_new(
		bytePtr(identity), C.size_t(len(identity)),
		bytePtr(secretKey), C.size_t(len(secretKey)),
		bytePtr(publicKey), C.size_t(len(publicKey)),
		bytePtr(declaration), C.size_t(len(declaration)),
		&handle,
	)
	runtime.KeepAlive(identity)
	runtime.KeepAlive(secretKey)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(declaration)
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

// keyPackage produces one KeyPackage ending no later than notAfterCap, its
// reference, and its private entry. Nothing of the private keys stays in the
// session; private is the caller's to persist and wipe.
func (s *Session) keyPackage(notAfterCap uint64) (message, reference, private []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, nil, nil, err
	}
	var m, r, p C.DpBuf
	if rc := C.dpmls_key_package(h, C.uint64_t(notAfterCap), &m, &r, &p); rc != 0 {
		return nil, nil, nil, statusError(rc)
	}
	return takeBuf(&m), takeBuf(&r), takeBuf(&p), nil
}

// installKeyPackage hands the session one private entry for the next join.
// The join drops it again, whether it succeeds or not.
func (s *Session) installKeyPackage(private []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	rc := C.dpmls_session_install_key_package(h, bytePtr(private), C.size_t(len(private)))
	runtime.KeepAlive(private)
	return statusError(rc)
}

// welcomeKeyPackageRefs lists the KeyPackage references a Welcome is
// addressed to.
func welcomeKeyPackageRefs(welcome []byte) ([][]byte, error) {
	var buf C.DpBuf
	rc := C.dpmls_welcome_key_package_refs(bytePtr(welcome), C.size_t(len(welcome)), &buf)
	runtime.KeepAlive(welcome)
	if rc != 0 {
		return nil, statusError(rc)
	}
	return decodeRefs(takeBuf(&buf))
}

// CommitAddMembers builds a Commit that adds these members and leaves it
// pending. The confirmed state does not move: RFC 9420 §14 forbids it, because
// at this moment nobody knows whether this Commit or somebody else's will be
// the one its epoch accepts. expectedEpoch is the confirmed epoch the Commit
// was built against, which is the value the server compares under its CAS.
//
// Every member must have been approved first (approve); the Rust gate refuses
// the whole Commit otherwise. CommitAddMembersVerified is the path that does
// both.
func (s *Session) CommitAddMembers(keyPackages [][]byte) (commit, welcome []byte, expectedEpoch uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, nil, 0, err
	}
	framed := frameKeyPackages(keyPackages)
	var (
		c, w  C.DpBuf
		epoch C.uint64_t
	)
	rc := C.dpmls_group_commit_add_members(
		h, bytePtr(framed), C.size_t(len(framed)), &c, &w, &epoch,
	)
	runtime.KeepAlive(framed)
	if rc != 0 {
		return nil, nil, 0, statusError(rc)
	}
	return takeBuf(&c), takeBuf(&w), uint64(epoch), nil
}

// CommitUpdate builds a Commit with no proposals, which rotates this device's
// own key material. Pending in the same way CommitAddMember is.
func (s *Session) CommitUpdate() (commit []byte, expectedEpoch uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, 0, err
	}
	var (
		c     C.DpBuf
		epoch C.uint64_t
	)
	if rc := C.dpmls_group_commit_update(h, &c, &epoch); rc != 0 {
		return nil, 0, statusError(rc)
	}
	return takeBuf(&c), uint64(epoch), nil
}

// CommitRemoveMembers builds a Commit that removes these leaves. Pending in the
// same way CommitAddMember is: the leaves stay in Roster until
// ApplyPendingCommit.
func (s *Session) CommitRemoveMembers(leafIndices []uint32) (commit []byte, expectedEpoch uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, 0, err
	}
	framed := frameLeafIndices(leafIndices)
	var (
		c     C.DpBuf
		epoch C.uint64_t
	)
	rc := C.dpmls_group_commit_remove_members(h, bytePtr(framed), C.size_t(len(framed)), &c, &epoch)
	runtime.KeepAlive(framed)
	if rc != 0 {
		return nil, 0, statusError(rc)
	}
	return takeBuf(&c), uint64(epoch), nil
}

// CommitReplaceMembers builds one Commit that removes these leaves and adds
// these members, and leaves it pending like CommitAddMembers. Every member
// added must have been approved first; CommitReplaceMembersVerified is the path
// that does both.
func (s *Session) CommitReplaceMembers(
	leafIndices []uint32, keyPackages [][]byte,
) (commit, welcome []byte, expectedEpoch uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, nil, 0, err
	}
	indices := frameLeafIndices(leafIndices)
	framed := frameKeyPackages(keyPackages)
	var (
		c, w  C.DpBuf
		epoch C.uint64_t
	)
	rc := C.dpmls_group_commit_replace_members(
		h, bytePtr(indices), C.size_t(len(indices)), bytePtr(framed), C.size_t(len(framed)), &c, &w, &epoch,
	)
	runtime.KeepAlive(indices)
	runtime.KeepAlive(framed)
	if rc != 0 {
		return nil, nil, 0, statusError(rc)
	}
	return takeBuf(&c), takeBuf(&w), uint64(epoch), nil
}

// Roster is every leaf of the confirmed tree. A pending Commit is not in it.
func (s *Session) Roster() ([]Leaf, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	if rc := C.dpmls_group_roster(h, &buf); rc != 0 {
		return nil, statusError(rc)
	}
	return decodeLeaves(takeBuf(&buf))
}

// ApplyPendingCommit promotes the pending Commit to confirmed. Nothing else
// does: this is the only call that moves the group to the epoch a Commit this
// device built would create.
func (s *Session) ApplyPendingCommit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	return statusError(C.dpmls_group_commit_apply(h))
}

// ClearPendingCommit drops the pending Commit and the next-epoch secrets it
// carries. Processing somebody else's Commit does the same thing on its own;
// this is for settling an outcome without the winning message in hand.
func (s *Session) ClearPendingCommit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	return statusError(C.dpmls_group_commit_clear(h))
}

func (s *Session) HasPendingCommit() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return false, err
	}
	var out C.uint8_t
	if rc := C.dpmls_group_has_pending_commit(h, &out); rc != 0 {
		return false, statusError(rc)
	}
	return out != 0, nil
}

// GroupID is the MLS group id. Groups this Keeper creates use the
// conversation id, which is what a join is checked against.
func (s *Session) GroupID() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	if rc := C.dpmls_group_id(h, &buf); rc != 0 {
		return nil, statusError(rc)
	}
	return takeBuf(&buf), nil
}

// Epoch is the confirmed epoch. A pending Commit never shows up here, which is
// what lets the rollback anchor follow this value without mistaking a lost CAS
// for a rewind (design §7.3.3).
func (s *Session) Epoch() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return 0, err
	}
	var out C.uint64_t
	if rc := C.dpmls_group_epoch(h, &out); rc != 0 {
		return 0, statusError(rc)
	}
	return uint64(out), nil
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

// Encrypt takes the generation SendPosition reported and moves the ratchet on.
// authenticatedData rides along in the clear and is covered by both the
// sender's signature and the AEAD tag, which is what makes a declaration
// carried in it the sender's word rather than the server's.
func (s *Session) Encrypt(plaintext, authenticatedData []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	rc := C.dpmls_group_encrypt(
		h,
		bytePtr(plaintext), C.size_t(len(plaintext)),
		bytePtr(authenticatedData), C.size_t(len(authenticatedData)),
		&buf,
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(authenticatedData)
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
		buf            C.DpBuf
		aad            C.DpBuf
		epoch          C.uint64_t
		senderIndex    C.uint32_t
		removed        C.uint8_t
		isApplication  C.uint8_t
		generation     C.uint32_t
		generationKnwn C.uint8_t
	)
	rc := C.dpmls_group_process(
		h, bytePtr(message), C.size_t(len(message)),
		&buf, &aad, &epoch, &senderIndex, &removed, &isApplication,
		&generation, &generationKnwn,
	)
	runtime.KeepAlive(message)
	if rc != 0 {
		return Processed{}, statusError(rc)
	}
	out := Processed{
		Epoch:             uint64(epoch),
		SenderLeafIndex:   uint32(senderIndex),
		Removed:           removed != 0,
		Application:       isApplication != 0,
		AuthenticatedData: takeBuf(&aad),
		Plaintext:         takeBuf(&buf),
	}
	// Nil rather than zero when the library could not report it. The two are
	// different answers and the fail-closed rule upstream of here depends on
	// being able to tell them apart.
	if generationKnwn != 0 {
		known := uint32(generation)
		out.KeyGeneration = &known
	}
	return out, nil
}

// approve hands the Rust gate the leaves Go verified for the next group
// operation on this session. That operation consumes the list either way.
func (s *Session) approve(leaves []Leaf) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	buf := encodeApprovals(leaves)
	rc := C.dpmls_session_approve(h, bytePtr(buf), C.size_t(len(buf)))
	runtime.KeepAlive(buf)
	return statusError(rc)
}

// approveRemovals hands the Rust rules the Removes Go judged authorized for
// the next group operation on this session. That operation consumes the list
// either way.
func (s *Session) approveRemovals(leaves []Leaf) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	buf := encodeRemovals(leaves)
	rc := C.dpmls_session_approve_removals(h, bytePtr(buf), C.size_t(len(buf)))
	runtime.KeepAlive(buf)
	return statusError(rc)
}

// processCollect reports the leaves message would bring in and what the
// Commit does, and leaves the group exactly as it was.
func (s *Session) processCollect(message []byte) ([]Leaf, CommitShape, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, CommitShape{}, err
	}
	var buf C.DpBuf
	rc := C.dpmls_group_process_collect(h, bytePtr(message), C.size_t(len(message)), &buf)
	runtime.KeepAlive(message)
	if rc != 0 {
		return nil, CommitShape{}, statusError(rc)
	}
	return decodeCollected(takeBuf(&buf))
}

// joinCollect reports every leaf of a Welcome's tree and keeps no group.
func (s *Session) joinCollect(welcome []byte) ([]Leaf, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	rc := C.dpmls_group_join_collect(h, bytePtr(welcome), C.size_t(len(welcome)), &buf)
	runtime.KeepAlive(welcome)
	if rc != 0 {
		return nil, statusError(rc)
	}
	return decodeLeaves(takeBuf(&buf))
}

// keyPackageLeaf reads the leaf a KeyPackage would add, without a session and
// without applying anything.
func keyPackageLeaf(keyPackage []byte) (Leaf, error) {
	var buf C.DpBuf
	rc := C.dpmls_key_package_leaf(bytePtr(keyPackage), C.size_t(len(keyPackage)), &buf)
	runtime.KeepAlive(keyPackage)
	if rc != 0 {
		return Leaf{}, statusError(rc)
	}
	leaves, err := decodeLeaves(takeBuf(&buf))
	if err != nil {
		return Leaf{}, err
	}
	if len(leaves) != 1 {
		return Leaf{}, errors.New("mls: key package leaf framing did not hold exactly one leaf")
	}
	return leaves[0], nil
}

// keyPackageNotAfter is the end of a KeyPackage's lifetime in Unix seconds.
func keyPackageNotAfter(keyPackage []byte) (uint64, error) {
	var out C.uint64_t
	rc := C.dpmls_key_package_not_after(bytePtr(keyPackage), C.size_t(len(keyPackage)), &out)
	runtime.KeepAlive(keyPackage)
	if rc != 0 {
		return 0, statusError(rc)
	}
	return uint64(out), nil
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

// ExportSecret is MLS-Exporter(label, context, n) of the confirmed epoch. The
// result is a key: the caller wipes it.
func (s *Session) ExportSecret(label, context []byte, n int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, err
	}
	var buf C.DpBuf
	rc := C.dpmls_group_export_secret(h,
		bytePtr(label), C.size_t(len(label)), bytePtr(context), C.size_t(len(context)), C.size_t(n), &buf)
	runtime.KeepAlive(label)
	runtime.KeepAlive(context)
	if rc != 0 {
		return nil, statusError(rc)
	}
	return takeBuf(&buf), nil
}

// ExportPendingSecret is the same for the epoch the pending Commit would
// create, and names that epoch. The Commit stays pending and the confirmed
// epoch does not move.
func (s *Session) ExportPendingSecret(label, context []byte, n int) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return nil, 0, err
	}
	var (
		buf   C.DpBuf
		epoch C.uint64_t
	)
	rc := C.dpmls_group_export_pending_secret(h,
		bytePtr(label), C.size_t(len(label)), bytePtr(context), C.size_t(len(context)), C.size_t(n), &epoch, &buf)
	runtime.KeepAlive(label)
	runtime.KeepAlive(context)
	if rc != 0 {
		return nil, 0, statusError(rc)
	}
	return takeBuf(&buf), uint64(epoch), nil
}

// SendPosition reports where this device's application ratchet stands without
// moving it. Three things about it matter to the caller: it compiles only in a
// build carrying both export_key_generation and secret_tree_access, the three
// values come from one call so they describe one moment, and it is a read
// rather than a claim — whatever holds the conversation lock has to span from
// here to the encryption that takes the number.
func (s *Session) SendPosition() (epoch uint64, leafIndex, generation uint32, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return 0, 0, 0, err
	}
	var (
		e    C.uint64_t
		leaf C.uint32_t
		gen  C.uint32_t
	)
	if rc := C.dpmls_group_send_position(h, &e, &leaf, &gen); rc != 0 {
		return 0, 0, 0, statusError(rc)
	}
	return uint64(e), uint32(leaf), uint32(gen), nil
}

// BurnGeneration consumes one application generation without encrypting
// anything. The key it derives is dropped on the Rust side and never crosses
// this boundary. The advance is only in memory until the caller persists the
// state.
func (s *Session) BurnGeneration() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.live()
	if err != nil {
		return err
	}
	return statusError(C.dpmls_group_burn_generation(h))
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
	// -4 is DPMLS_ERR_UNTRUSTED: a leaf nobody approved reached the gate.
	if rc == -4 {
		return fmt.Errorf("%w (status %d): %s", ErrLeafUntrusted, int(rc), msg)
	}
	// -5 is DPMLS_ERR_FROM_SELF: this session's own leaf sent the message.
	// Not ErrFailed, because the display path answers it from local history.
	if rc == -5 {
		return fmt.Errorf("%w (status %d): %s", chatstate.ErrOwnMessage, int(rc), msg)
	}
	// -6 is DPMLS_ERR_UNAUTHORIZED: a Remove or a proposal type nobody
	// approved reached the rules. Go judges first, so reaching this is the
	// Rust half refusing what the Go half would have refused.
	if rc == -6 {
		return &chatstate.UnauthorizedCommitError{Reason: "the mls rules refused a proposal nobody approved"}
	}
	return fmt.Errorf("%w (status %d): %s", ErrFailed, int(rc), msg)
}
