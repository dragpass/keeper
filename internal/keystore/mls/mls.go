// Package mls links the MLS (RFC 9420) implementation Keeper uses and keeps
// the serialized group state it produces inside the existing chat state record.
//
// # What is here and what is not
//
// This is the skeleton: the library is linked, its policy is fixed, and the
// bytes it serializes reach disk through chatstate's whole-file replacement.
// The send and receive ordering that has to sit on top of it — naming the
// generation before consuming it, burning an uncertain one after a crash,
// holding the lock across the encryption — is not here yet.
//
// # Build tag
//
// The binding needs cgo and a Rust static library, so it sits behind the `mls`
// build tag and a stub answers ErrUnavailable without it. The default build is
// byte-for-byte what it was: the Linux release still builds with CGO_ENABLED=0
// and still ships a static binary, which linking this would end. Keeping the
// tag off by default is what lets the library be measured and reviewed before
// that trade is made rather than as a side effect of making it.
//
// # What the state blob holds
//
// More than ratchet state. mls-rs's snapshot carries the epoch secrets, the
// secret tree, the key schedule, the private tree and, in the same structure,
// this device's leaf signature secret key. So the record's seal key is
// protecting a signing key and not only decryption material, and losing the
// file to an attacker who also has the seal key means losing the ability to
// prove this device authored anything.
//
// # Memory
//
// mls-rs protects key material with zeroize, which overwrites a buffer when the
// value holding it is dropped. Measured coverage (mls-rs 0.56.0 /
// mls-rs-core 0.27.0): the serialized state and prior-epoch blobs, the key
// schedule's five secrets, the secret tree's node secrets, every derived
// message key and nonce, the signature and HPKE secret keys, and application
// plaintext.
//
// That is the whole of the protection, and it is narrower than the list makes
// it sound: it covers one buffer at the moment its owner is dropped. It does
// not reach copies made along the way, the allocation a growing Vec abandons,
// pages the OS wrote to swap, or the image in a core dump. Neither mls-rs nor
// any of its 112 dependencies calls mlock, VirtualLock, madvise or mprotect —
// zeroize's own documentation puts those explicitly out of scope — so the Rust
// side allocates from a plain global heap and Keeper's memguard arena does not
// extend over any of it. Secrets in this package's Go buffers are not covered
// either unless the caller wipes them.
package mls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// ErrUnavailable — this binary was built without the MLS library. Distinct from
// every other failure so a caller never reads "no group" when the real answer is
// "no library".
var ErrUnavailable = errors.New("mls: this build does not include the MLS library")

// WireForm is the framing a message actually went out in, read back off the
// encoded bytes. Asserting on this rather than on the setting that produced it
// is what would catch an upstream default changing under us.
type WireForm uint8

const (
	WireFormOther WireForm = iota
	WireFormPublicMessage
	WireFormPrivateMessage
	WireFormWelcome
	WireFormKeyPackage
	WireFormGroupInfo
)

func (w WireForm) String() string {
	switch w {
	case WireFormPublicMessage:
		return "PublicMessage"
	case WireFormPrivateMessage:
		return "PrivateMessage"
	case WireFormWelcome:
		return "Welcome"
	case WireFormKeyPackage:
		return "KeyPackage"
	case WireFormGroupInfo:
		return "GroupInfo"
	default:
		return "other"
	}
}

// Processed is the outcome of applying one inbound message. Plaintext is set
// only for an application message and is the caller's to wipe.
type Processed struct {
	Epoch       uint64
	Removed     bool
	Application bool
	Plaintext   []byte

	// SenderLeafIndex is SenderData.leaf_index, which the wire format keeps
	// encrypted. It is half of the four-slot name of an inbound position and
	// there is no way to learn it except by decrypting.
	SenderLeafIndex uint32

	// AuthenticatedData is the sender's cleartext declaration.
	AuthenticatedData []byte

	// KeyGeneration is the generation the library derived its keys from, or
	// nil when it could not tell. Nil is an answer and never a zero: upstream
	// reaches its None by folding an extraction error into a default, so a
	// substituted zero would be indistinguishable from a checked match.
	KeyGeneration *uint32
}

// Persist flushes the session's group state into the conversation's record.
//
// The flush and the write are two steps because only the second is durable.
// mls-rs advances its secret tree in memory and writes nothing until it is
// asked, so anything that moved the group forward is lost unless this runs
// after it. Pairing an advance with this call is an invariant of the layer
// above; nothing below checks it.
func Persist(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (uint64, error) {
	blob, err := s.Flush()
	if err != nil {
		return 0, err
	}
	return store.SaveGroupState(conversationID, wm, blob)
}

// Restore loads the conversation's stored group state into the session. It
// reports false when the conversation has no group state yet, which is an
// ordinary state and not an error.
func Restore(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (bool, error) {
	blob, err := store.LoadGroupState(conversationID, wm)
	if err != nil {
		return false, err
	}
	if len(blob) == 0 {
		return false, nil
	}
	return true, s.Load(blob)
}

// ────────────────────────────────────────────────────────────────────────
// The seam chatstate drives its transactions through.
// ────────────────────────────────────────────────────────────────────────

// Cipher adapts a Session to chatstate's SendCipher and ReceiveCipher. It adds
// no state of its own: every method is one Session call, and the ordering,
// the lock and the durability all belong to chatstate.
//
// Load is called on every transaction even when the session already holds the
// group, because the record is the authority on where the ratchet is and
// another process may have moved it since this session last looked.
//
// Every path that can bring a leaf into the group — applying somebody's
// Commit, and building an Add — goes through verifier first. What a
// successful verification would record (a first-use pin, a newer declaration)
// is the verifier's to hold until the caller has seen the whole chatstate
// transaction succeed; this type never writes it.
type Cipher struct {
	session  *Session
	verifier LeafVerifier
}

func NewCipher(s *Session, verifier LeafVerifier) *Cipher {
	return &Cipher{session: s, verifier: verifier}
}

func (c *Cipher) Load(groupState []byte) error { return c.session.Load(groupState) }

func (c *Cipher) Peek() (chatstate.Position, error) {
	epoch, leaf, generation, err := c.session.SendPosition()
	if err != nil {
		return chatstate.Position{}, err
	}
	return chatstate.Position{
		Epoch:           epoch,
		SenderLeafIndex: leaf,
		// Fixed rather than asked: encrypt_control_messages is pinned false,
		// so a Commit goes out as a PublicMessage and consumes nothing. The
		// handshake ratchet never advances, which is what leaves the send
		// discipline with this one axis to defend. Flipping that setting
		// brings the other axis back, and mls-rs exposes neither a peek nor a
		// burn for it.
		ContentType: chatstate.ContentTypeApplication,
		Generation:  uint64(generation),
	}, nil
}

func (c *Cipher) Burn() error { return c.session.BurnGeneration() }

func (c *Cipher) Seal(plaintext, authenticatedData []byte) ([]byte, error) {
	return c.session.Encrypt(plaintext, authenticatedData)
}

func (c *Cipher) State() ([]byte, error) { return c.session.Flush() }

// BuildCommit builds a Commit and leaves it pending. mls-rs refuses a second
// one with MlsError::ExistingPendingCommit, so the "at most one pending" rule
// §7.3.1 states is enforced a layer below this and not only by the record.
func (c *Cipher) BuildCommit(plan chatstate.CommitPlan) (chatstate.BuiltCommit, error) {
	if len(plan.RemoveAccountIDs) > 0 {
		if len(plan.AddKeyPackages) > 0 {
			return chatstate.BuiltCommit{}, errors.New("mls: a commit plan adds or removes, not both")
		}
		commit, expected, err := c.commitRemoveAccounts(plan.RemoveAccountIDs)
		if err != nil {
			return chatstate.BuiltCommit{}, err
		}
		return chatstate.BuiltCommit{Commit: commit, ExpectedEpoch: expected}, nil
	}
	if len(plan.AddKeyPackages) == 0 {
		commit, expected, err := c.session.CommitUpdate()
		if err != nil {
			return chatstate.BuiltCommit{}, err
		}
		return chatstate.BuiltCommit{Commit: commit, ExpectedEpoch: expected}, nil
	}
	commit, welcome, expected, err := c.session.CommitAddMembersVerified(plan.AddKeyPackages, c.verifier)
	if err != nil {
		return chatstate.BuiltCommit{}, err
	}
	return chatstate.BuiltCommit{Commit: commit, Welcome: welcome, ExpectedEpoch: expected}, nil
}

// commitRemoveAccounts removes every leaf of each account. An account with no
// leaf in the confirmed tree is refused rather than skipped: a Commit that
// removes less than it was asked to would read as the removal having happened.
func (c *Cipher) commitRemoveAccounts(accountIDs []string) ([]byte, uint64, error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, 0, err
	}
	var indices []uint32
	for _, want := range accountIDs {
		found := false
		for _, leaf := range leaves {
			account, _, err := ParseCredentialIdentity(leaf.Identity)
			if err != nil {
				return nil, 0, err
			}
			if account == want {
				indices = append(indices, leaf.Index)
				found = true
			}
		}
		if !found {
			return nil, 0, errors.New("mls: an account to remove has no leaf in the group")
		}
	}
	return c.session.CommitRemoveMembers(indices)
}

// ConfirmedAccounts reads the confirmed roster, which a pending Commit is not
// part of. Every identity is parsed strictly: a leaf this cannot attribute to
// an account is an error, never a leaf that silently latches nobody.
func (c *Cipher) ConfirmedAccounts() ([]string, error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, err
	}
	accounts := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		account, _, err := ParseCredentialIdentity(leaf.Identity)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(accounts, account) {
			accounts = append(accounts, account)
		}
	}
	slices.Sort(accounts)
	return accounts, nil
}

func (c *Cipher) ApplyPending() error { return c.session.ApplyPendingCommit() }

func (c *Cipher) ClearPending() error { return c.session.ClearPendingCommit() }

func (c *Cipher) ApplyMessage(message []byte) (uint64, bool, error) {
	processed, err := c.session.ProcessVerified(message, c.verifier)
	if err != nil {
		return 0, false, err
	}
	return processed.Epoch, processed.Removed, nil
}

func (c *Cipher) Epoch() (uint64, error) { return c.session.Epoch() }

func (c *Cipher) Open(message []byte) (chatstate.Opened, error) {
	processed, err := c.session.ProcessVerified(message, c.verifier)
	if err != nil {
		return chatstate.Opened{}, err
	}
	return chatstate.Opened{
		Epoch:             processed.Epoch,
		SenderLeafIndex:   processed.SenderLeafIndex,
		Application:       processed.Application,
		Removed:           processed.Removed,
		AuthenticatedData: processed.AuthenticatedData,
		KeyGeneration:     processed.KeyGeneration,
		Plaintext:         processed.Plaintext,
	}, nil
}

// ────────────────────────────────────────────────────────────────────────
// This device's leaf.
// ────────────────────────────────────────────────────────────────────────

// ErrNoLeafKey — the device has not enrolled a leaf key (mls_leaf_declare).
var ErrNoLeafKey = errors.New("mls: this device has no leaf signature key")

// ErrNoLeafDeclaration — the device's active leaf record was written by an
// older Keeper: 0.0.43 kept no declaration, and 0.0.44's is signed over the
// version 1 canonical every verifier now refuses. Neither is used. `enroll`
// mints a new key and, once promoted, replaces the record.
var ErrNoLeafDeclaration = errors.New("mls: this device's leaf key has no current declaration; enroll again")

// ErrLeafKeyUnreadable — the active leaf record is there but cannot be read.
var ErrLeafKeyUnreadable = errors.New("mls: this device's leaf key record is unreadable")

const (
	credentialIdentityDomain  = "dragpass.mls.credential"
	credentialIdentityVersion = "1"
)

// CredentialIdentity is the BasicCredential identity of a device's leaf. It
// carries both halves of what a leaf declaration binds, which is what lets a
// verifier match a leaf to its declaration (design §5.3 steps 2 and 6).
//
//	dragpass.mls.credential|1|<account_id>|<device_id>
func CredentialIdentity(accountID, deviceID string) []byte {
	return []byte(strings.Join([]string{
		credentialIdentityDomain, credentialIdentityVersion, accountID, deviceID,
	}, "|"))
}

// ParseCredentialIdentity accepts only the exact bytes CredentialIdentity
// would produce, so one identity never has two spellings that compare unequal.
func ParseCredentialIdentity(identity []byte) (accountID, deviceID string, err error) {
	parts := strings.Split(string(identity), "|")
	if len(parts) != 4 || parts[0] != credentialIdentityDomain || parts[1] != credentialIdentityVersion ||
		!isLowerUUID(parts[2]) || !isLowerUUID(parts[3]) ||
		!bytes.Equal(identity, CredentialIdentity(parts[2], parts[3])) {
		return "", "", errors.New("mls: credential identity is not a dragpass device identity")
	}
	return parts[2], parts[3], nil
}

// isLowerUUID is the shape a leaf declaration requires of both ids, checked
// here too so an identity no declaration could match is refused on sight.
func isLowerUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c < '0' || c > '9') && (c < 'a' || c > 'f'):
			return false
		}
	}
	return true
}

// DeviceLeaf is the public half of the leaf record a device session was built
// from. Declaration is the extension payload the session embeds.
type DeviceLeaf struct {
	AccountID   string
	DeviceID    string
	PublicKey   []byte
	Declaration []byte
}

// NewDeviceSession builds a session that signs as this device's declared leaf.
// It is the only way to get a Session, so every group this device joins or
// creates shares the one key its declaration names. It reads the active slot
// only: a pending key, one the server has not accepted, never signs anything.
//
// The slot is read once, and the leaf it held comes back with the session.
// A caller that needs to know which leaf it is signing as uses that value and
// never reads the slot again: a promote in between would make the second read
// name a different key than the one the session holds. Whoever must keep the
// leaf from changing while the session is in use holds
// keychain.WithMLSLeafLock around the call; this function takes no lock.
func NewDeviceSession(store keychain.SecretStore) (*Session, DeviceLeaf, error) {
	if !Available() {
		return nil, DeviceLeaf{}, ErrUnavailable
	}
	key, found, err := keychain.GetMLSLeafKey(store)
	if err != nil {
		return nil, DeviceLeaf{}, ErrLeafKeyUnreadable
	}
	defer secure.Zeroize(key.SecretKey)
	if !found {
		return nil, DeviceLeaf{}, ErrNoLeafKey
	}
	if !key.Usable() {
		return nil, DeviceLeaf{}, ErrNoLeafDeclaration
	}
	session, err := openSession(
		CredentialIdentity(key.AccountID, key.DeviceID), key.SecretKey, key.PublicKey, key.Declaration,
	)
	if err != nil {
		return nil, DeviceLeaf{}, err
	}
	return session, DeviceLeaf{
		AccountID: key.AccountID, DeviceID: key.DeviceID, PublicKey: key.PublicKey, Declaration: key.Declaration,
	}, nil
}

// MaxKeyPackagesPerCall bounds one mls_key_package_generate call. The pool is
// the extension's and the server's to size; this only keeps a single request
// from asking for an unbounded amount of work.
const MaxKeyPackagesPerCall = 32

// MaxKeyPackageBytes is the largest KeyPackage this Keeper hands out. ariadne
// stores each one in account_mls_key_packages.key_package VARBINARY(8192) and
// refuses anything larger, so a bigger one would be minted only to be
// rejected on upload.
const MaxKeyPackageBytes = 8192

// KeyPackage is one single-use KeyPackage and the end of its lifetime, which
// is the not_after the client declares when it uploads it. Public material
// only.
type KeyPackage struct {
	Message  []byte
	NotAfter uint64
}

// KeyPackages produces n single-use KeyPackages, each carrying the active
// declaration this session was built with and ending no later than
// notAfterCap — the declaration's own not_after, which a KeyPackage embedding
// it must not outlive. There is no last-resort KeyPackage. One over
// MaxKeyPackageBytes fails the call rather than being dropped or cut: a short
// batch would read as success.
//
// The second result holds each KeyPackage's private keys, for the owner's
// KeyPackage pool (chatstate.Store.AddKeyPackages). It must be stored before
// the first result is handed to anyone — a KeyPackage whose keys were lost is
// one nobody can be added through — and wiped after. The session keeps none
// of it.
func (s *Session) KeyPackages(n int, notAfterCap uint64) ([]KeyPackage, []chatstate.KeyPackagePoolEntry, error) {
	if n < 1 || n > MaxKeyPackagesPerCall {
		return nil, nil, errors.New("mls: key package count is out of range")
	}
	out := make([]KeyPackage, 0, n)
	pool := make([]chatstate.KeyPackagePoolEntry, 0, n)
	fail := func(err error) ([]KeyPackage, []chatstate.KeyPackagePoolEntry, error) {
		for _, e := range pool {
			secure.Zeroize(e.Private)
		}
		return nil, nil, err
	}
	for i := 0; i < n; i++ {
		kp, ref, private, err := s.keyPackage(notAfterCap)
		if err != nil {
			return fail(err)
		}
		pool = append(pool, chatstate.KeyPackagePoolEntry{Ref: ref, Private: private})
		if len(kp) > MaxKeyPackageBytes {
			return fail(errors.New("mls: a key package exceeds the size the server stores"))
		}
		notAfter, err := keyPackageNotAfter(kp)
		if err != nil {
			return fail(err)
		}
		if notAfter > notAfterCap {
			return fail(errors.New("mls: a key package outlives its leaf declaration"))
		}
		pool[i].NotAfter = notAfter
		out = append(out, KeyPackage{Message: kp, NotAfter: notAfter})
	}
	return out, pool, nil
}

// ErrNoKeyPackageForWelcome — this device holds no private keys for any
// KeyPackage the Welcome is addressed to: it expired, was never kept, or was
// already used.
var ErrNoKeyPackageForWelcome = errors.New("mls: no key package private keys for this welcome")

// JoinFromPool joins a conversation from a Welcome addressed to one of this
// device's KeyPackages, taking that KeyPackage's private keys from the
// owner's pool, and persists the group.
//
// The order is the point. The group state is written first and the pool entry
// deleted second. A crash between the two leaves an entry behind, which is
// harmless: the server marked that KeyPackage consumed when it served it and
// will not hand it out again. The other order could lose the invitation — the
// keys gone and the group never written.
//
// mls-rs deletes the KeyPackage from its own repository when the joined group
// is written to storage, outside any transaction (design §15). That repository
// is the session's in-memory custody here, not a durable store, so its delete
// is not a second atomicity unit: the only durable delete is the pool's, and
// it follows the group state write.
//
// What v would record (first-use pins) is the caller's to commit once this
// returns nil, as with every verified operation.
func (s *Session) JoinFromPool(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	welcome []byte,
	v LeafVerifier,
	now time.Time,
) error {
	refs, err := welcomeKeyPackageRefs(welcome)
	if err != nil {
		return err
	}
	entry, err := store.LookupKeyPackage(refs, now)
	if errors.Is(err, chatstate.ErrKeyPackageNotInPool) {
		return ErrNoKeyPackageForWelcome
	}
	if err != nil {
		return err
	}
	err = s.installKeyPackage(entry.Private)
	secure.Zeroize(entry.Private)
	if err != nil {
		return err
	}
	if err := s.JoinVerified(welcome, v); err != nil {
		return err
	}
	if _, err := Persist(store, conversationID, wm, s); err != nil {
		return err
	}
	return store.DeleteKeyPackage(entry.Ref, now)
}

// decodeRefs reads dpmls_welcome_key_package_refs' framing strictly.
func decodeRefs(buf []byte) ([][]byte, error) {
	bad := errors.New("mls: key package reference framing is malformed")
	r := leafReader{buf: buf}
	count, ok := r.u32()
	if !ok || count > maxLeaves {
		return nil, bad
	}
	refs := make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		ref, ok := r.prefixed()
		if !ok {
			return nil, bad
		}
		refs = append(refs, ref)
	}
	if len(r.buf) != r.at {
		return nil, bad
	}
	return refs, nil
}

// ────────────────────────────────────────────────────────────────────────
// Leaf verification: Go verifies, Rust enforces.
// ────────────────────────────────────────────────────────────────────────

// ErrLeafUntrusted — a leaf that would enter the group is not vouched for by
// its account (design §5.3, §13 CHAT_MLS_LEAF_UNTRUSTED). Nothing was applied.
var ErrLeafUntrusted = errors.New("mls: a leaf entering the group is not vouched for by its account")

// Leaf is one leaf entering this device's view of a group.
type Leaf struct {
	// Index is the leaf's place in the tree. Zero and meaningless for the leaf
	// a KeyPackage would add, which has no place yet.
	Index        uint32
	Identity     []byte
	SignatureKey []byte

	// Declaration is the payload of the leaf declaration extension, and nil
	// when the leaf carries none — which is itself a refusal.
	Declaration []byte

	// Entering is true for a leaf this operation brings into the group: an
	// Add, whether this device builds it or applies somebody's Commit, and a
	// member's replacement leaf in an update path. It is false for a leaf a
	// Welcome's tree already holds, which the members accepted when it
	// entered. Freshness checks — is this the newest declaration seen for the
	// account, has it expired — apply in full only to entering leaves: a member
	// who has since rotated still sits in older groups under the old leaf until
	// it replaces it there, so a Welcome's tree is refused a superseded leaf
	// only after a grace period, and never an expired one.
	Entering bool
}

// LeafVerifier runs design §5.3 over the leaves one operation brings in.
//
// It judges them as one unit: nil only when every leaf passes. It must not
// persist anything. Whatever a success would record belongs to the caller to
// write after the whole operation has succeeded, because a leaf that passed
// here can still be part of an operation that fails later.
type LeafVerifier interface {
	VerifyLeaves(leaves []Leaf) error
}

// verifyLeaves is the Go half. A nil verifier with leaves to judge is a
// refusal, not a pass: no caller gets to opt out by forgetting one.
func verifyLeaves(v LeafVerifier, leaves []Leaf) error {
	if len(leaves) == 0 {
		return nil
	}
	if v == nil {
		return ErrLeafUntrusted
	}
	return v.VerifyLeaves(leaves)
}

// ProcessVerified applies one inbound message, verifying every leaf it brings
// in first.
//
// A PublicMessage — which is how every Commit this integration sends goes out
// (encrypt_control_messages is pinned false) — is processed twice. The collect
// pass applies it to a copy with every leaf admitted and reports the new
// leaves; the Go verifier judges them; the enforce pass applies it for real
// with the Rust gate admitting only what was approved. mls-rs persists nothing
// until the caller flushes, so the collect pass leaves no trace. It is the
// enforce pass that decides: the collect pass's view is only what the verifier
// was asked about.
//
// Anything else is processed once under the resting gate, which admits the
// current members and nobody new. A PrivateMessage Commit that adds a member
// is therefore refused rather than verified; nothing this Keeper sends is one.
func (s *Session) ProcessVerified(message []byte, v LeafVerifier) (Processed, error) {
	form, err := WireFormOf(message)
	if err != nil {
		return Processed{}, err
	}
	if form == WireFormPublicMessage {
		leaves, err := s.processCollect(message)
		if err != nil {
			return Processed{}, err
		}
		markEntering(leaves)
		if err := verifyLeaves(v, leaves); err != nil {
			return Processed{}, err
		}
		if err := s.approve(leaves); err != nil {
			return Processed{}, err
		}
	}
	return s.Process(message)
}

// JoinVerified joins from a Welcome after verifying every leaf of its tree —
// the committer's, every other member's, and this device's own. A joiner has
// no earlier state that vouched for any of them, so every leaf gets the
// binding checks. None of them is entering: the tree is the group as its
// members already accepted it, so no expiry check runs, a superseded
// declaration is refused only once its grace period has passed, and nothing
// here advances the newest-declaration record.
func (s *Session) JoinVerified(welcome []byte, v LeafVerifier) error {
	leaves, err := s.joinCollect(welcome)
	if err != nil {
		return err
	}
	if err := verifyLeaves(v, leaves); err != nil {
		return err
	}
	if err := s.approve(leaves); err != nil {
		return err
	}
	return s.Join(welcome)
}

// CommitAddMembersVerified verifies the leaves these KeyPackages would add, as
// one unit, and only then builds the Add. The KeyPackages are read without a
// group, so a refused set builds nothing and leaves no pending Commit.
func (s *Session) CommitAddMembersVerified(
	keyPackages [][]byte, v LeafVerifier,
) (commit, welcome []byte, expectedEpoch uint64, err error) {
	if len(keyPackages) == 0 || len(keyPackages) > MaxKeyPackagesPerCall {
		return nil, nil, 0, errors.New("mls: add member count is out of range")
	}
	leaves := make([]Leaf, 0, len(keyPackages))
	for _, kp := range keyPackages {
		leaf, err := keyPackageLeaf(kp)
		if err != nil {
			return nil, nil, 0, err
		}
		leaf.Entering = true
		leaves = append(leaves, leaf)
	}
	if err := verifyLeaves(v, leaves); err != nil {
		return nil, nil, 0, err
	}
	if err := s.approve(leaves); err != nil {
		return nil, nil, 0, err
	}
	return s.CommitAddMembers(keyPackages)
}

// CommitAddMemberVerified is CommitAddMembersVerified for one member.
func (s *Session) CommitAddMemberVerified(
	keyPackage []byte, v LeafVerifier,
) (commit, welcome []byte, expectedEpoch uint64, err error) {
	return s.CommitAddMembersVerified([][]byte{keyPackage}, v)
}

// frameKeyPackages frames KeyPackages the way gate::decode_key_packages reads
// them: u32 count, then each u32-length-prefixed, big-endian.
func frameKeyPackages(keyPackages [][]byte) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(keyPackages)))
	for _, kp := range keyPackages {
		out = binary.BigEndian.AppendUint32(out, uint32(len(kp)))
		out = append(out, kp...)
	}
	return out
}

// frameLeafIndices frames leaf indices the way gate::decode_leaf_indices reads
// them: u32 count, then each u32, big-endian.
func frameLeafIndices(indices []uint32) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(indices)))
	for _, i := range indices {
		out = binary.BigEndian.AppendUint32(out, i)
	}
	return out
}

// markEntering flags every leaf a Commit brings in — its Adds and a
// replacement leaf from an update path, which is exactly what the collect
// pass's diff reports.
func markEntering(leaves []Leaf) {
	for i := range leaves {
		leaves[i].Entering = true
	}
}

// maxLeaves mirrors gate::MAX_LEAVES on the Rust side.
const maxLeaves = 4096

// encodeApprovals frames leaves the way gate::decode_approvals reads them:
// u32 count, then per leaf a u32-length-prefixed identity, signature key and
// declaration, big-endian.
func encodeApprovals(leaves []Leaf) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(leaves)))
	for _, l := range leaves {
		for _, field := range [][]byte{l.Identity, l.SignatureKey, l.Declaration} {
			out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
			out = append(out, field...)
		}
	}
	return out
}

// decodeLeaves reads gate::encode_leaves' framing strictly: a truncated,
// oversized or trailing-byte buffer is an error, never a shorter list.
func decodeLeaves(buf []byte) ([]Leaf, error) {
	bad := errors.New("mls: leaf list framing is malformed")
	r := leafReader{buf: buf}
	count, ok := r.u32()
	if !ok || count > maxLeaves {
		return nil, bad
	}
	leaves := make([]Leaf, 0, count)
	for i := uint32(0); i < count; i++ {
		var l Leaf
		if l.Index, ok = r.u32(); !ok {
			return nil, bad
		}
		if l.Identity, ok = r.prefixed(); !ok {
			return nil, bad
		}
		if l.SignatureKey, ok = r.prefixed(); !ok {
			return nil, bad
		}
		present, ok := r.take(1)
		if !ok {
			return nil, bad
		}
		switch present[0] {
		case 0:
		case 1:
			if l.Declaration, ok = r.prefixed(); !ok {
				return nil, bad
			}
			// Present and empty stays distinguishable from absent.
			if l.Declaration == nil {
				l.Declaration = []byte{}
			}
		default:
			return nil, bad
		}
		leaves = append(leaves, l)
	}
	if len(r.buf) != r.at {
		return nil, bad
	}
	return leaves, nil
}

type leafReader struct {
	buf []byte
	at  int
}

func (r *leafReader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.buf)-r.at {
		return nil, false
	}
	out := r.buf[r.at : r.at+n]
	r.at += n
	return out, true
}

func (r *leafReader) u32() (uint32, bool) {
	b, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

func (r *leafReader) prefixed() ([]byte, bool) {
	n, ok := r.u32()
	if !ok {
		return nil, false
	}
	b, ok := r.take(int(n))
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}
