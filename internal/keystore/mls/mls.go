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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// ErrUnavailable — this binary was built without the MLS library. Distinct from
// every other failure so a caller never reads "no group" when the real answer is
// "no library".
var ErrUnavailable = errors.New("mls: this build does not include the MLS library")

// ErrFailed marks a refusal or failure of the MLS operation itself — the
// library rejected a message, a Commit could not be built, a plan named a
// member the group does not hold — as distinct from the storage around it. The
// protocol edge answers it with CHAT_MLS_FAILED and never with a storage code.
var ErrFailed = errors.New("mls operation failed")

// ErrGroupMismatch — a Welcome produced a group whose id is not the
// conversation it was handed in for. Groups this Keeper creates are named by
// their conversation id, so this is a Welcome for some other conversation.
var ErrGroupMismatch = errors.New("mls: the welcome is for a different conversation's group")

func failed(reason string) error { return fmt.Errorf("%w: %s", ErrFailed, reason) }

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
	defer secure.Zeroize(blob)
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
	defer secure.Zeroize(blob)
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
// successful verification records (a first-use pin, a newer declaration) is
// written by the session once the MLS operation has succeeded, before
// chatstate writes the state (LeafVerifier); this type writes nothing itself.
type Cipher struct {
	session  *Session
	verifier LeafVerifier

	// authority is the evidence the next applied Commit is judged by, handed
	// in by chatstate before every Open and ApplyMessage (AuthorityReceiver).
	// Unset it is empty, which admits only R1 and R2.
	authority chatstate.CommitAuthority

	// lastChange is what the last Commit this cipher applied did.
	lastChange *chatstate.CommitChange
}

var (
	_ chatstate.AuthorityReceiver = (*Cipher)(nil)
	_ chatstate.ChangeReporter    = (*Cipher)(nil)
)

// SetCommitAuthority is chatstate.AuthorityReceiver.
func (c *Cipher) SetCommitAuthority(auth chatstate.CommitAuthority) { c.authority = auth }

// LastCommitChange is chatstate.ChangeReporter.
func (c *Cipher) LastCommitChange() (chatstate.CommitChange, bool) {
	if c.lastChange == nil {
		return chatstate.CommitChange{}, false
	}
	return *c.lastChange, true
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

// CreateGroup starts the conversation's group, for chatstate.Store.CreateGroup.
func (c *Cipher) CreateGroup(groupID []byte) error { return c.session.CreateGroup(groupID) }

// BuildCommit builds a Commit and leaves it pending. mls-rs refuses a second
// one with MlsError::ExistingPendingCommit, so the "at most one pending" rule
// §7.3.1 states is enforced a layer below this and not only by the record.
func (c *Cipher) BuildCommit(plan chatstate.CommitPlan) (chatstate.BuiltCommit, error) {
	kinds := 0
	for _, present := range []bool{
		len(plan.AddKeyPackages) > 0, len(plan.RemoveAccountIDs) > 0, len(plan.Replace) > 0, len(plan.Rejoin) > 0,
	} {
		if present {
			kinds++
		}
	}
	if kinds > 1 {
		return chatstate.BuiltCommit{}, failed("a commit plan adds, removes, replaces or rejoins, never two of them")
	}
	if len(plan.Rejoin) > 0 {
		commit, welcome, expected, err := c.commitRejoinAccounts(plan.Rejoin)
		if err != nil {
			return chatstate.BuiltCommit{}, err
		}
		return chatstate.BuiltCommit{Commit: commit, Welcome: welcome, ExpectedEpoch: expected}, nil
	}
	if len(plan.Replace) > 0 {
		commit, welcome, expected, err := c.commitReplaceAccounts(plan.Replace)
		if err != nil {
			return chatstate.BuiltCommit{}, err
		}
		return chatstate.BuiltCommit{Commit: commit, Welcome: welcome, ExpectedEpoch: expected}, nil
	}
	if len(plan.RemoveAccountIDs) > 0 {
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
//
// The plan was judged before this (chatstate.requireAuthorizedPlan), so the
// leaves it names are exactly the Removes approved to the Rust rules.
func (c *Cipher) commitRemoveAccounts(accountIDs []string) ([]byte, uint64, error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, 0, err
	}
	var removed []Leaf
	for _, want := range accountIDs {
		found := false
		for _, leaf := range leaves {
			account, _, err := ParseCredentialIdentity(leaf.Identity)
			if err != nil {
				return nil, 0, err
			}
			if account == want {
				removed = append(removed, leaf)
				found = true
			}
		}
		if !found {
			return nil, 0, failed("an account to remove has no leaf in the group")
		}
	}
	if err := c.session.approveRemovals(removed); err != nil {
		return nil, 0, err
	}
	return c.session.CommitRemoveMembers(leafIndices(removed))
}

func leafIndices(leaves []Leaf) []uint32 {
	out := make([]uint32, len(leaves))
	for i, l := range leaves {
		out[i] = l.Index
	}
	return out
}

// commitRejoinAccounts re-seats each account (design Q6): every leaf it holds
// in the confirmed tree goes out and its new KeyPackage comes in, in one
// Commit, which is the R2 shape every receiver accepts. The caller has
// verified the account's signed rejoin request against this KeyPackage's leaf.
//
// An account with no leaf in the authenticated tree is refused and never added:
// the unusable-Welcome case a rejoin exists for always leaves the account's
// dead leaf there. Adding one that is not there would let whoever lists
// rejoins (the server) have an account of its choosing added.
func (c *Cipher) commitRejoinAccounts(members []chatstate.RejoinMember) (commit, welcome []byte, expected uint64, err error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, nil, 0, err
	}
	var (
		removed []Leaf
		kps     [][]byte
	)
	for _, m := range members {
		account, _, err := KeyPackageIdentity(m.KeyPackage)
		if err != nil || account != m.AccountID {
			return nil, nil, 0, fmt.Errorf("%w: the rejoin key package names another account", ErrLeafUntrusted)
		}
		held := false
		for _, l := range leaves {
			owner, _, err := ParseCredentialIdentity(l.Identity)
			if err != nil {
				return nil, nil, 0, err
			}
			if owner == m.AccountID {
				removed = append(removed, l)
				held = true
			}
		}
		if !held {
			return nil, nil, 0, &chatstate.UnauthorizedCommitError{
				Reason: "a rejoin names an account with no leaf in the group",
			}
		}
		kps = append(kps, m.KeyPackage)
	}
	if err := c.session.approveRemovals(removed); err != nil {
		return nil, nil, 0, err
	}
	return c.session.CommitReplaceMembersVerified(leafIndices(removed), kps, c.verifier)
}

// commitReplaceAccounts builds the M4.4 replace: for each account, every leaf
// whose key is not the replacement's goes out and the replacement's KeyPackage
// comes in, all in one Commit.
//
// The KeyPackage is held to two things §5.3 does not check on its own: its
// credential names the account being replaced, and its leaf signs with the
// key the permit named. The first keeps a KeyPackage of another account from
// taking this one's place; the second keeps any other key of the same account
// — the old device's, or one the server swapped in — from being the one the
// latch then accepts as the replacement. Either mismatch is ErrLeafUntrusted,
// decided before anything is built. The leaf then goes through the full §5.3
// verification as an entering leaf, freshness included.
//
// An account with no leaf under another key is refused rather than turned
// into a bare Add: there is nothing it replaces.
func (c *Cipher) commitReplaceAccounts(members []chatstate.ReplaceMember) (commit, welcome []byte, expected uint64, err error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, nil, 0, err
	}
	var (
		removed []Leaf
		kps     [][]byte
	)
	for _, m := range members {
		leaf, err := keyPackageLeaf(m.KeyPackage)
		if err != nil {
			return nil, nil, 0, err
		}
		account, _, err := ParseCredentialIdentity(leaf.Identity)
		if err != nil || account != m.AccountID {
			return nil, nil, 0, fmt.Errorf("%w: the replacement key package names another account", ErrLeafUntrusted)
		}
		fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.SignatureKey)
		if err != nil || fingerprint != m.NewFingerprint {
			return nil, nil, 0, fmt.Errorf("%w: the replacement key package is not the key the permit names", ErrLeafUntrusted)
		}
		found := false
		for _, l := range leaves {
			held, _, err := ParseCredentialIdentity(l.Identity)
			if err != nil {
				return nil, nil, 0, err
			}
			if held != m.AccountID {
				continue
			}
			heldFingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(l.SignatureKey)
			if err != nil {
				return nil, nil, 0, failed("a leaf in the group has an unreadable signature key")
			}
			if heldFingerprint != m.NewFingerprint {
				removed = append(removed, l)
				found = true
			}
		}
		if !found {
			return nil, nil, 0, failed("an account to replace has no other leaf in the group")
		}
		kps = append(kps, m.KeyPackage)
	}
	if err := c.session.approveRemovals(removed); err != nil {
		return nil, nil, 0, err
	}
	return c.session.CommitReplaceMembersVerified(leafIndices(removed), kps, c.verifier)
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

// ConfirmedLeaves reads the confirmed roster with each leaf's key
// fingerprint, for the M4.4 latch, under the same strict parsing.
func (c *Cipher) ConfirmedLeaves() ([]chatstate.RosterLeaf, error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return nil, err
	}
	out := make([]chatstate.RosterLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		account, _, err := ParseCredentialIdentity(leaf.Identity)
		if err != nil {
			return nil, err
		}
		fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.SignatureKey)
		if err != nil {
			return nil, failed("a leaf in the group has an unreadable signature key")
		}
		out = append(out, chatstate.RosterLeaf{AccountID: account, Fingerprint: fingerprint})
	}
	return out, nil
}

func (c *Cipher) ApplyPending() error { return c.session.ApplyPendingCommit() }

func (c *Cipher) ClearPending() error { return c.session.ClearPendingCommit() }

func (c *Cipher) ApplyMessage(message []byte) (uint64, bool, error) {
	processed, change, err := c.session.processAuthorized(message, c.verifier, c.authority)
	if err != nil {
		return 0, false, err
	}
	c.lastChange = change
	return processed.Epoch, processed.Removed, nil
}

func (c *Cipher) Epoch() (uint64, error) { return c.session.Epoch() }

func (c *Cipher) ExportSecret(label, context []byte, n int) ([]byte, error) {
	return c.session.ExportSecret(label, context, n)
}

func (c *Cipher) ExportPendingSecret(label, context []byte, n int) ([]byte, uint64, error) {
	return c.session.ExportPendingSecret(label, context, n)
}

// Open applies or decrypts one inbound message. For an application message it
// also names the sender, from the credential of the leaf at SenderLeafIndex in
// the group's own tree: the leaf that signed the message, in the epoch it was
// sent in, which is the only source for who sent it that the server does not
// choose. A sender this cannot attribute is a refusal, never an anonymous
// message.
func (c *Cipher) Open(message []byte) (chatstate.Opened, error) {
	processed, change, err := c.session.processAuthorized(message, c.verifier, c.authority)
	if err != nil {
		return chatstate.Opened{}, err
	}
	c.lastChange = change
	var account, device string
	if processed.Application {
		if account, device, err = c.senderOf(processed.SenderLeafIndex); err != nil {
			secure.Zeroize(processed.Plaintext)
			return chatstate.Opened{}, err
		}
	}
	return chatstate.Opened{
		SenderAccountID:   account,
		SenderDeviceID:    device,
		Epoch:             processed.Epoch,
		SenderLeafIndex:   processed.SenderLeafIndex,
		Application:       processed.Application,
		Removed:           processed.Removed,
		AuthenticatedData: processed.AuthenticatedData,
		KeyGeneration:     processed.KeyGeneration,
		Plaintext:         processed.Plaintext,
	}, nil
}

// SenderOf names the leaf at this index from the confirmed tree, for the
// sealed copy of a message this device sends.
func (c *Cipher) SenderOf(leafIndex uint32) (chatstate.Sender, error) {
	account, device, err := c.senderOf(leafIndex)
	if err != nil {
		return chatstate.Sender{}, err
	}
	return chatstate.Sender{AccountID: account, DeviceID: device}, nil
}

func (c *Cipher) senderOf(leafIndex uint32) (accountID, deviceID string, err error) {
	leaves, err := c.session.Roster()
	if err != nil {
		return "", "", err
	}
	for _, leaf := range leaves {
		if leaf.Index == leafIndex {
			return ParseCredentialIdentity(leaf.Identity)
		}
	}
	return "", "", failed("the sending leaf is not in the group")
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
		return "", "", failed("credential identity is not a dragpass device identity")
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
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(key.PublicKey)
	if err != nil {
		return nil, DeviceLeaf{}, ErrLeafKeyUnreadable
	}
	session, err := openSession(
		CredentialIdentity(key.AccountID, key.DeviceID), key.SecretKey, key.PublicKey, key.Declaration,
	)
	if err != nil {
		return nil, DeviceLeaf{}, err
	}
	session.leafFingerprint = fingerprint
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

// KeyPackageLeaf reads the leaf a KeyPackage would add, without a group: its
// identity, its signature key and its declaration payload. The index is 0.
func KeyPackageLeaf(keyPackage []byte) (Leaf, error) { return keyPackageLeaf(keyPackage) }

// KeyPackageIdentity reads the account and device a KeyPackage's leaf claims,
// without a group. It is how a caller that asked the server for one member's
// KeyPackage checks it was handed that member's and not some other account's:
// §5.3 would accept any account whose declaration verifies, so it cannot tell
// the two apart on its own.
func KeyPackageIdentity(keyPackage []byte) (accountID, deviceID string, err error) {
	leaf, err := keyPackageLeaf(keyPackage)
	if err != nil {
		return "", "", err
	}
	return ParseCredentialIdentity(leaf.Identity)
}

// ErrNoKeyPackageForWelcome — this device holds no private keys for any
// KeyPackage the Welcome is addressed to: it expired, was never kept, was
// already used, or belonged to a leaf a promote has since replaced
// (chatstate.DropKeyPackagesExcept). None of these is retryable; the inviter
// has to invite again.
var ErrNoKeyPackageForWelcome = errors.New("mls: no key package private keys for this welcome")

// JoinFromPool joins a conversation from a Welcome addressed to one of this
// device's KeyPackages, taking that KeyPackage's private keys from the
// owner's pool, and persists the group at the epoch it joined at. A record
// with a pending Commit refuses the join and keeps the pool entry.
//
// The order is the point. The group state is written first and the pool entry
// deleted second; the other order could lose the invitation — the keys gone
// and the group never written. A crash between the two leaves the entry's
// private keys behind, and those must not stay: the entry is claimed for this
// conversation before the state write and the joined record names it, so the
// next pool open deletes it (chatstate's pool sweep).
//
// mls-rs deletes the KeyPackage from its own repository when the joined group
// is written to storage, outside any transaction (design §15). That repository
// is the session's in-memory custody here, not a durable store, so its delete
// is not a second atomicity unit: the only durable delete is the pool's, and
// it follows the group state write.
//
// An entry minted under another leaf than the one this session signs as is
// refused like a missing one (ErrNoKeyPackageForWelcome): its KeyPackage
// embeds a leaf this device no longer signs with, so the group it joined
// would name a key the session does not hold. The entry is kept, because a
// refusal persists nothing; the next promote's drop removes it.
//
// What v records (first-use pins) is written when the Welcome has been
// joined and before the group state is, as with every verified operation
// (LeafVerifier). A refused join writes none.
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
	defer secure.Zeroize(entry.Private)
	return s.joinFromEntry(store, conversationID, wm, welcome, entry, v, now)
}

// joinFromEntry is JoinFromPool from the pool entry on.
//
// An entry with no leaf recorded was written before 0.0.50 and is still
// used. If the active leaf has not changed since it was minted it is a valid
// KeyPackage, and refusing it would make every invitation in flight across
// the upgrade unjoinable. The cost is the one case the label exists for: a
// device that promoted a rotation under 0.0.49 still holds unlabelled
// entries of its old leaf, and a Welcome to one of them is joined with the
// new leaf's session. That window closes at the device's next promote, which
// drops every unlabelled entry.
func (s *Session) joinFromEntry(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	welcome []byte,
	entry chatstate.KeyPackagePoolEntry,
	v LeafVerifier,
	now time.Time,
) error {
	if entry.Leaf != "" && entry.Leaf != s.leafFingerprint {
		return ErrNoKeyPackageForWelcome
	}
	if err := s.installKeyPackage(entry.Private); err != nil {
		return err
	}
	if err := s.JoinVerified(welcome, v); err != nil {
		return err
	}
	groupID, err := s.GroupID()
	if err != nil {
		return err
	}
	if !bytes.Equal(groupID, []byte(conversationID)) {
		return ErrGroupMismatch
	}
	blob, err := s.Flush()
	if err != nil {
		return err
	}
	defer secure.Zeroize(blob)
	epoch, err := s.Epoch()
	if err != nil {
		return err
	}
	ownLeaf, err := s.OwnLeafIndex()
	if err != nil {
		return err
	}
	if err := store.ClaimKeyPackage(entry.Ref, conversationID); err != nil {
		return err
	}
	if _, err := store.SaveJoinedGroupState(conversationID, wm, blob, epoch, ownLeaf, entry.Ref); err != nil {
		return err
	}
	if err := afterJoinedStateSaved(); err != nil {
		return err
	}
	return store.DeleteKeyPackage(entry.Ref, now)
}

// afterJoinedStateSaved runs between the joined group state write and the
// pool delete. A test sets it to stop there, the way a crash would.
var afterJoinedStateSaved = func() error { return nil }

// OwnLeafIndex is this device's leaf in the group the session holds: the
// library's current member index, read from the group state itself.
func (s *Session) OwnLeafIndex() (uint32, error) {
	_, leaf, _, err := s.SendPosition()
	return leaf, err
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
// VerifyLeaves judges them as one unit: nil only when every leaf passes. It
// must not persist anything, because it runs before MLS has authenticated the
// operation: a Commit's leaves are collected from a pass that admits every
// leaf, so a message that later fails MLS could otherwise plant a first-use
// pin for a key of its choosing.
//
// Commit writes what the last successful VerifyLeaves staged. The session
// calls it once the MLS operation those leaves belong to has succeeded, and
// before it returns, so before the caller writes the group state that holds
// them. That order is what closes the crash window: the state is never on
// disk with a leaf whose account key is not pinned, so a crash can at most
// leave a pin whose state was not written, and the retry pins the same key
// again. The other order let a crash leave the group without the pin, and the
// next leaf of that account was then taken as a first use whatever key it
// carried.
type LeafVerifier interface {
	VerifyLeaves(leaves []Leaf) error
	Commit() error
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

// recordVerified is Commit for an operation whose MLS half has just
// succeeded. With no leaves VerifyLeaves never ran, so whatever v holds is
// from some earlier operation and is not written.
func recordVerified(v LeafVerifier, leaves []Leaf) error {
	if len(leaves) == 0 {
		return nil
	}
	return v.Commit()
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
	processed, _, err := s.processAuthorized(message, v, chatstate.CommitAuthority{})
	return processed, err
}

// ProcessAuthorized is ProcessVerified with the evidence the Commit authority
// rules judge by (chatstate/authority.go). ProcessVerified judges with none,
// which admits only a Commit whose every Remove is the committer's own
// account or paired with an Add of the same account.
func (s *Session) ProcessAuthorized(message []byte, v LeafVerifier, auth chatstate.CommitAuthority) (Processed, error) {
	processed, _, err := s.processAuthorized(message, v, auth)
	return processed, err
}

// processAuthorized is where the collect pass is judged twice: the leaves by
// v (§5.3), then the Commit's Adds and Removes by the authority rules. Both
// are decided before the enforce pass, which applies nothing either half did not
// approve. It also reports what the Commit did.
func (s *Session) processAuthorized(
	message []byte, v LeafVerifier, auth chatstate.CommitAuthority,
) (Processed, *chatstate.CommitChange, error) {
	form, err := WireFormOf(message)
	if err != nil {
		return Processed{}, nil, err
	}
	if form != WireFormPublicMessage {
		processed, err := s.Process(message)
		return processed, nil, err
	}
	leaves, shape, err := s.processCollect(message)
	if err != nil {
		return Processed{}, nil, err
	}
	markEntering(leaves)
	if err := verifyLeaves(v, leaves); err != nil {
		return Processed{}, nil, err
	}
	// After the leaves: a Commit that brings in a leaf its account does not
	// vouch for is refused as that, and only a Commit whose leaves are all
	// genuine is judged on whether its committer may make the change.
	change, err := s.judgeCollected(shape, auth)
	if err != nil {
		return Processed{}, nil, err
	}
	if err := s.approve(leaves); err != nil {
		return Processed{}, nil, err
	}
	processed, err := s.Process(message)
	if err != nil {
		return Processed{}, nil, err
	}
	if err := recordVerified(v, leaves); err != nil {
		secure.Zeroize(processed.Plaintext)
		return Processed{}, nil, err
	}
	return processed, change, nil
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
	if err := s.Join(welcome); err != nil {
		return err
	}
	return recordVerified(v, leaves)
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
	if commit, welcome, expectedEpoch, err = s.CommitAddMembers(keyPackages); err != nil {
		return nil, nil, 0, err
	}
	if err := recordVerified(v, leaves); err != nil {
		return nil, nil, 0, err
	}
	return commit, welcome, expectedEpoch, nil
}

// CommitReplaceMembersVerified is CommitAddMembersVerified for a Commit that
// also removes leafIndices: the leaves the KeyPackages would add are verified
// as one unit and as entering leaves, and a refused set builds nothing.
func (s *Session) CommitReplaceMembersVerified(
	leafIndices []uint32, keyPackages [][]byte, v LeafVerifier,
) (commit, welcome []byte, expectedEpoch uint64, err error) {
	if len(leafIndices) == 0 || len(keyPackages) == 0 || len(keyPackages) > MaxKeyPackagesPerCall {
		return nil, nil, 0, errors.New("mls: replace member count is out of range")
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
	if commit, welcome, expectedEpoch, err = s.CommitReplaceMembers(leafIndices, keyPackages); err != nil {
		return nil, nil, 0, err
	}
	if err := recordVerified(v, leaves); err != nil {
		return nil, nil, 0, err
	}
	return commit, welcome, expectedEpoch, nil
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
	r := leafReader{buf: buf}
	leaves, ok := r.leaves()
	if !ok || len(r.buf) != r.at {
		return nil, errors.New("mls: leaf list framing is malformed")
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
