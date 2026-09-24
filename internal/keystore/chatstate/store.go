// store.go — the locked read / modify / persist cycle every operation runs.
//
// Each exported operation is one complete cycle under the conversation's lock:
// load the anchor, load and judge the file, change it, replace the file
// atomically, then raise the anchor. Nothing is cached across the lock, because
// a cache is a copy of the state that no longer has a lock protecting it.
//
// The anchor is written twice per reservation and the order is the whole point.
// Raising the ceiling first and committing the file second means the only crash
// window leaves the file *ahead* of the anchor, which is the harmless
// direction: those positions are already spent on disk. The other order would
// leave the file behind the anchor, which is indistinguishable from a restored
// backup and would lock a conversation on every crash.

package chatstate

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// MaxReserveCount bounds one reservation. A caller that wants more positions
// than this is not composing a message.
const MaxReserveCount = 64

// Store is one owner account's view of the chat state directory. It holds
// derived key material, so it is built per operation and closed after.
type Store struct {
	// HistoryPolicy is the tunable part of the local message history. Its
	// zero value is the shipped behaviour; see history.go for which of its
	// values are still undecided.
	HistoryPolicy HistoryPolicy

	secrets     keychain.SecretStore
	root        string
	owner       string
	nameKey     []byte
	aeadKey     []byte
	historyKey  []byte
	poolKey     []byte
	lockTimeout time.Duration
}

// Reservation is the answer to "which positions may I encrypt with". It is
// returned only after the consumption of those positions is on disk and
// fsynced, so a crash between this answer and the encryption loses a message
// and never reuses a position. A gap in the chain is ordinary; a repeat is not
// recoverable.
type Reservation struct {
	Epoch           uint64
	FirstChainIndex uint64
	Count           int
	Generation      uint64
}

// Open returns the owner's store, minting the seal key on first use.
func Open(secrets keychain.SecretStore, ownerAccountID string) (*Store, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	master, err := loadSealKey(secrets, ownerAccountID)
	if err != nil {
		if !errors.Is(err, keychain.ErrSecretNotFound) {
			return nil, err
		}
		if master, err = createSealKey(secrets, root, ownerAccountID); err != nil {
			return nil, err
		}
	}
	defer secure.Zeroize(master)
	return &Store{
		secrets:     secrets,
		root:        root,
		owner:       ownerAccountID,
		nameKey:     deriveSubkey(master, nameSubkeyLabel),
		aeadKey:     deriveSubkey(master, aeadSubkeyLabel),
		historyKey:  deriveSubkey(master, historySubkeyLabel),
		poolKey:     deriveSubkey(master, keyPackagePoolSubkeyLabel),
		lockTimeout: LockTimeout,
	}, nil
}

// Close drops the derived key material. Callers defer it.
func (s *Store) Close() {
	secure.Zeroize(s.nameKey)
	secure.Zeroize(s.aeadKey)
	secure.Zeroize(s.historyKey)
	secure.Zeroize(s.poolKey)
}

// Reserve consumes count chain positions and returns them. The consumption is
// durable before this returns; see Reservation.
func (s *Store) Reserve(conversationID string, count int, wm ServerWatermark) (Reservation, error) {
	if count < 1 || count > MaxReserveCount {
		return Reservation{}, fmt.Errorf("reserve count must be 1..%d", MaxReserveCount)
	}
	var out Reservation
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		loaded := rec.Generation
		first := rec.NextIndex
		need := first + uint64(count)
		anchor.ReservedBefore = max(anchor.ReservedBefore, need)
		if err := saveAnchor(s.secrets, p.tag, anchor); err != nil {
			return err
		}
		rec.NextIndex = need
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = Reservation{
			Epoch:           rec.Epoch,
			FirstChainIndex: first,
			Count:           count,
			Generation:      rec.Generation,
		}
		return nil
	})
	return out, err
}

// CommitOutbox stores the ciphertext built for a reserved position. The stored
// entry is authoritative: a second call with the same client message id returns
// what is already there and writes nothing, so a retransmission after a lost
// response is the same bytes rather than a second encryption.
func (s *Store) CommitOutbox(
	conversationID string, wm ServerWatermark, entry OutboxEntry,
) (OutboxEntry, bool, error) {
	if len(entry.IV) != ivBytes ||
		len(entry.Ciphertext) == 0 || len(entry.Ciphertext) > MaxCiphertextBytes {
		return OutboxEntry{}, false, errors.New("outbox entry has an unusable ciphertext")
	}
	var (
		stored  OutboxEntry
		created bool
	)
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if existing, ok := rec.findOutbox(entry.ClientMessageID); ok {
			stored, created = existing, false
			return nil
		}
		if entry.Position.Epoch != rec.Epoch || entry.Position.Generation >= rec.NextIndex {
			return ErrPositionNotReserved
		}
		if rec.positionTaken(entry.Position) || rec.sealedBySendPath(entry.Position) {
			return ErrPositionTaken
		}
		loaded := rec.Generation
		rec.appendOutbox(entry)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		stored, created = entry, true
		return nil
	})
	return stored, created, err
}

// ReadOutbox returns the stored ciphertext for a client message id.
func (s *Store) ReadOutbox(
	conversationID string, wm ServerWatermark, clientMessageID string,
) (OutboxEntry, error) {
	var out OutboxEntry
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		entry, ok := rec.findOutbox(clientMessageID)
		if !ok {
			return ErrNotFound
		}
		out = entry
		return nil
	})
	return out, err
}

// MarkReceived records an inbound position and reports whether this delivery
// was the first. Persisting the mark before the caller is told it may show the
// message is what keeps a redelivery from advancing the state twice.
//
// A position that does not name its ratchet is refused rather than stored: an
// unnamed axis collapses two senders' chains onto one key, and the answer this
// returns would then be "redelivery" for a message nobody has seen.
func (s *Store) MarkReceived(
	conversationID string, wm ServerWatermark, pos Position,
) (bool, uint64, error) {
	if !pos.ContentType.valid() {
		return false, 0, errors.New("received position must name a content type")
	}
	var (
		first      bool
		generation uint64
	)
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.receivedContains(pos) {
			first, generation = false, rec.Generation
			return nil
		}
		loaded := rec.Generation
		rec.appendReceived(pos)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		first, generation = true, rec.Generation
		return nil
	})
	return first, generation, err
}

// SaveGroupState replaces the conversation's serialized MLS state with the
// blob the library handed out and returns the record generation that now
// carries it. The store writes a copy; the caller keeps blob and wipes it. Send and Receive persist the state themselves as part of their
// transactions; this is for the paths that move the group without sending or
// receiving, such as establishing it in the first place.
//
// The blob is not only ratchet state: the MLS snapshot puts this device's leaf
// signature secret key in the same structure as the epoch secrets. The seal key
// in front of these files is therefore standing in front of a signing key too,
// which is why the erasure paths have to reach the seal key and not just the
// files.
//
// The blob is written through the same whole-file replacement every other
// change here takes. That matters more than it looks: mls-rs asks its storage
// provider for atomicity but only "optimally", so nothing upstream supplies it.
// Routing the blob through this path is what turns that suggestion into a
// property — a crash leaves the record holding the previous group state or the
// new one, never a spliced half of each.
func (s *Store) SaveGroupState(
	conversationID string, wm ServerWatermark, blob []byte,
) (uint64, error) {
	if len(blob) == 0 {
		return 0, errors.New("group state blob is empty")
	}
	var generation uint64
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		loaded := rec.Generation
		rec.GroupState = bytes.Clone(blob)
		rec.RemovedFromGroup = false
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		generation = rec.Generation
		return nil
	})
	return generation, err
}

// LoadGroupState returns a copy of the stored blob, which the caller owns and
// wipes, or nil when this conversation has never held one. Nil is an answer, not a failure: a conversation exists before
// its group does.
func (s *Store) LoadGroupState(conversationID string, wm ServerWatermark) ([]byte, error) {
	var blob []byte
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		blob = bytes.Clone(rec.GroupState)
		return nil
	})
	return blob, err
}

// Purge erases every trace of one owner's chat state: the files, the anchors,
// and the seal key.
func Purge(secrets keychain.SecretStore, ownerAccountID string) (int, error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	return purgeOwner(secrets, root, ownerTag(ownerAccountID))
}

// PurgeAll erases the chat state of every owner on this device. It starts from
// the directory listing rather than from an owner the caller names, because a
// device reset has no account to name: it is what a user reaches for once the
// server-side account is gone.
func PurgeAll(secrets keychain.SecretStore) (int, error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var failures []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		count, err := purgeOwner(secrets, root, entry.Name())
		removed += count
		failures = append(failures, err)
	}
	return removed, errors.Join(failures...)
}

// purgeOwner erases one owner's directory, the anchors of every conversation in
// it, and the seal key. The seal key goes last and its removal is what makes
// the erasure final — a state file restored from a backup afterwards cannot be
// opened under the key that replaces it, so a purge cannot be used to clear a
// latched NeedsRekey and then bring the rewound file back.
//
// Owner-scoped, and it has to be: the seal key is one per owner account, so
// there is no per-conversation key to drop. Reaching for this to forget a
// single conversation would take every other conversation of that account with
// it. What it reaches, and what it does not:
//
//   - The record files, which hold the group state and the sealed local
//     history, the KeyPackage pool, and the temp files beside them.
//   - The keyring anchor of each conversation and the owner's seal key.
//   - Not a copy of any of those made earlier. A filesystem backup still holds
//     the records, and a keychain backup or a synced keychain still holds the
//     seal key that opens them. Deleting a key here is a deletion from this
//     keyring, not from wherever else it already went.
//
// A failing step does not stop the ones after it. Each step stands alone, and
// stopping early leaves more behind than carrying on does: it would skip the
// seal key, which is the step that makes whatever survived unopenable. The
// caller is told what failed and every step is idempotent, so a retry costs
// nothing.
func purgeOwner(secrets keychain.SecretStore, root, tag string) (int, error) {
	dir := filepath.Join(root, tag)
	conversations, err := conversationTagsIn(dir)
	failures := []error{err}
	removed := 0
	for _, conversation := range conversations {
		if err := deleteAnchor(secrets, conversation); err != nil {
			failures = append(failures, err)
			continue
		}
		removed++
	}
	failures = append(failures, os.RemoveAll(dir))
	if err := secrets.Delete(config.Service, sealKeyAccountForTag(tag)); err != nil &&
		!errors.Is(err, keychain.ErrSecretNotFound) {
		failures = append(failures, err)
	}
	return removed, errors.Join(failures...)
}

// ────────────────────────────────────────────────────────────────────────
// Paths and the locked cycle.
// ────────────────────────────────────────────────────────────────────────

type convPaths struct {
	tag    string
	dir    string
	record string
	lock   string

	// scrub is set by withConversation and collects the group state buffers
	// of the cycle. Nil for paths built outside one.
	scrub *groupStateScrub
}

// groupStateScrub is every group state one locked cycle held: the buffer
// each record was read with, and whatever the record holds when the cycle
// ends (the state the MLS layer handed back to be written). The serialized
// state carries the leaf signature secret key, so none of it should outlive
// the lock. What this cannot reach is listed on withConversation.
type groupStateScrub struct {
	records []*Record
	buffers [][]byte
}

func (p convPaths) track(rec *Record) {
	if p.scrub == nil {
		return
	}
	p.scrub.records = append(p.scrub.records, rec)
	p.scrub.buffers = append(p.scrub.buffers, rec.GroupState)
}

func (g *groupStateScrub) wipe() {
	for _, b := range g.buffers {
		secure.Zeroize(b)
	}
	for _, rec := range g.records {
		secure.Zeroize(rec.GroupState)
	}
}

func (s *Store) ownerDir() string { return filepath.Join(s.root, ownerTag(s.owner)) }

func (s *Store) paths(conversationID string) convPaths {
	tag := s.conversationTag(conversationID)
	dir := s.ownerDir()
	return convPaths{
		tag:    tag,
		dir:    dir,
		record: filepath.Join(dir, tag+recordSuffix),
		lock:   filepath.Join(dir, tag+lockSuffix),
	}
}

// conversationTagsIn lists the conversations one owner has state for. Directory
// enumeration stands in for an index; nothing outside a single file needs to be
// consistent, so there is no index to drift. The tags cannot be turned back
// into conversation ids, which is all the local operations need and one fewer
// thing the directory gives away.
func conversationTagsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var tags []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), recordSuffix) {
			continue
		}
		tags = append(tags, strings.TrimSuffix(entry.Name(), recordSuffix))
	}
	return tags, nil
}

// withConversation runs fn under the conversation's lock and wipes every group
// state buffer the cycle held when it ends, so an operation hands nothing of
// it back except through a copy (LoadGroupState).
//
// Best effort, and only for the buffers this package owns. Not reached: the
// copies the Go runtime makes of its own accord (a slice that grew, a moved
// stack, memory the GC has not yet reused), the base64 decode json.Unmarshal
// runs over the record body, and the pooled encoder buffer json.Marshal keeps
// after writeRecord; the record body itself is wiped on both paths.
func (s *Store) withConversation(conversationID string, fn func(convPaths) error) error {
	p := s.paths(conversationID)
	if err := ensureOwnerOnlyDir(s.root, p.dir); err != nil {
		return err
	}
	release, err := acquireConversationLock(p.lock, s.lockTimeout)
	if err != nil {
		return err
	}
	defer release()
	p.scrub = &groupStateScrub{}
	defer p.scrub.wipe()
	return fn(p)
}

// ensureOwnerOnlyDir creates each directory in order and narrows it to this
// user. MkdirAll alone is not enough on Windows, where the mode argument is
// ignored; the parent is named explicitly rather than left to MkdirAll so that
// it is narrowed too, instead of keeping whatever the config directory hands
// down.
func ensureOwnerOnlyDir(dirs ...string) error {
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create chat state directory: %w", err)
		}
		if err := restrictDirToOwner(dir); err != nil {
			return err
		}
	}
	return nil
}

// loadChecked returns the record only if both rollback axes accept it. A
// refusal latches NeedsRekey on the anchor rather than returning a soft error,
// because a caller that can retry into a rewound state has the same problem as
// one that never checked.
func (s *Store) loadChecked(
	p convPaths, conversationID string, wm ServerWatermark,
) (*Record, Anchor, error) {
	rec, anchor, err := s.loadLocal(p, conversationID)
	if err != nil {
		return nil, anchor, err
	}
	return s.judgeWatermark(p, rec, anchor, wm)
}

// loadLocal is loadChecked's first half: the checks that need only the file
// and the keyring. SaveJoinedGroupState runs the halves apart, because the
// watermark describes a chain that only exists once the join has moved the
// record onto its epoch and leaf.
func (s *Store) loadLocal(p convPaths, conversationID string) (*Record, Anchor, error) {
	anchor, err := loadAnchor(s.secrets, p.tag)
	if err != nil {
		return nil, Anchor{}, err
	}
	if anchor.NeedsRekey {
		return nil, anchor, ErrRekeyRequired
	}
	rec, err := s.readRecord(p, conversationID)
	if err != nil {
		return nil, anchor, err
	}
	if rec == nil {
		// A missing file under an anchor that has authorized anything is a
		// deletion, not a first use: those positions were handed out and the
		// only record of that is gone.
		if anchor.Generation > 0 || anchor.ReservedBefore > 0 {
			return nil, anchor, s.latchRekey(p.tag, anchor, RekeyCauseStateMissing)
		}
		rec = newRecord(s.owner, conversationID)
		p.track(rec)
	}
	if anchor.rewoundLocally(rec) {
		return nil, anchor, s.latchRekey(p.tag, anchor, RekeyCauseRollback)
	}
	return rec, anchor, nil
}

// judgeWatermark is loadChecked's second half.
func (s *Store) judgeWatermark(
	p convPaths, rec *Record, anchor Anchor, wm ServerWatermark,
) (*Record, Anchor, error) {
	if anchor.watermarkAhead(rec, wm) {
		return nil, anchor, s.latchRekey(p.tag, anchor, RekeyCauseWatermarkAhead)
	}
	return rec, anchor.advancedBy(rec, wm), nil
}

// latchRekey sets NeedsRekey. Nothing in this package clears it again.
func (s *Store) latchRekey(tag string, anchor Anchor, cause RekeyCause) error {
	return s.latchRekeyDetail(tag, anchor, RekeyDetail{Cause: cause})
}

// latchRekeyDetail is latchRekey with what the latch was about. The first
// cause and its detail are kept: a second reason never rewrites the first.
func (s *Store) latchRekeyDetail(tag string, anchor Anchor, detail RekeyDetail) error {
	anchor.NeedsRekey = true
	if anchor.RekeyCause == "" {
		anchor.RekeyCause = detail.Cause
		anchor.RekeyEpoch = detail.Epoch
		anchor.RekeyCommitterAccountID = detail.CommitterAccountID
		anchor.RekeyCommitterDeviceID = detail.CommitterDeviceID
	}
	if err := saveAnchor(s.secrets, tag, anchor); err != nil {
		return err
	}
	if detail.Cause == RekeyCauseUnauthorizedCommit {
		return &RekeyLatchedError{Detail: detail}
	}
	return ErrRekeyRequired
}

// rekeyDetail reads why the conversation is latched, with a zero Cause when
// it is not or when the latch predates the cause being recorded. It judges
// nothing.
func (s *Store) rekeyDetail(p convPaths) (RekeyDetail, error) {
	anchor, err := loadAnchor(s.secrets, p.tag)
	if err != nil || !anchor.NeedsRekey {
		return RekeyDetail{}, err
	}
	return RekeyDetail{
		Cause:              anchor.RekeyCause,
		Epoch:              anchor.RekeyEpoch,
		CommitterAccountID: anchor.RekeyCommitterAccountID,
		CommitterDeviceID:  anchor.RekeyCommitterDeviceID,
	}, nil
}

// commit bumps the generation, replaces the file, and then raises the anchor to
// match. The anchor write is last so the crash window leaves the file ahead.
func (s *Store) commit(p convPaths, rec *Record, loadedGeneration uint64, anchor Anchor) error {
	rec.Generation = loadedGeneration + 1
	if err := s.writeRecord(p, rec, loadedGeneration); err != nil {
		return err
	}
	crashAt(CrashCommitAfterFile)
	anchor.Generation = rec.Generation
	if rec.Epoch > anchor.Epoch {
		// The anchor's half of Record.enterEpoch, which explains why the
		// ceiling is per-epoch. It lands here rather than beside the record's
		// half so that the ceiling and the epoch it belongs to move in one
		// keyring write, and after the file that advanced into it is already
		// on disk.
		anchor.ReservedBefore = rec.NextIndex
	}
	anchor.Epoch = rec.Epoch
	return saveAnchor(s.secrets, p.tag, anchor)
}

// ────────────────────────────────────────────────────────────────────────
// File I/O.
// ────────────────────────────────────────────────────────────────────────

func (s *Store) readRecord(p convPaths, conversationID string) (*Record, error) {
	s.sweepTempFiles(p.dir)
	sealed, err := os.ReadFile(p.record)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	body, generation, err := openRecord(s.aeadKey, s.owner, conversationID, sealed)
	if err != nil {
		return nil, err
	}
	defer secure.Zeroize(body)
	var rec Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, errSealedRecordMalformed
	}
	p.track(&rec)
	if rec.SchemaVersion != SchemaVersion ||
		rec.Generation != generation ||
		rec.OwnerAccountID != s.owner ||
		rec.ConversationID != conversationID {
		return nil, errSealedRecordMalformed
	}
	return &rec, nil
}

func (s *Store) writeRecord(p convPaths, rec *Record, loadedGeneration uint64) error {
	current, err := onDiskGeneration(p.record)
	if err != nil {
		return err
	}
	if current != loadedGeneration {
		return ErrConflict
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sealed, sealErr := sealRecord(s.aeadKey, rec, body)
	secure.Zeroize(body)
	if sealErr != nil {
		return sealErr
	}
	return replaceFile(p.dir, p.record, sealed)
}

// replaceFile is the atomic half: a temp file in the same directory, fsynced,
// renamed over the target, and the directory fsynced after. A crash anywhere in
// here leaves either the previous file or the new one, never a mixture. POSIX
// guarantees the rename; the Windows equivalent is on the ADR's measure-first
// list and is not assumed here.
func replaceFile(dir, path string, data []byte) error {
	tmp, err := os.CreateTemp(dir, tempPrefix)
	if err != nil {
		return fmt.Errorf("create chat state temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	// Before the bytes, not after: the file must never be readable by anyone
	// else, not even for the window between the write and the rename.
	if err := restrictFileToOwner(tmpName); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

// sweepTempFiles removes leftovers from an interrupted write. A temp file is
// never a load candidate, which is what makes a half-written one harmless: the
// only file that is ever read is the one a completed rename put in place.
func (s *Store) sweepTempFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), tempPrefix) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

// onDiskGeneration reads the cleartext header only. It answers "did the file
// change since this operation read it", so a tampered header costs a spurious
// conflict and never a silent overwrite.
func onDiskGeneration(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()
	var header [13]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, errSealedRecordMalformed
		}
		return 0, err
	}
	if [4]byte(header[0:4]) != fileMagic {
		return 0, errSealedRecordMalformed
	}
	return binary.BigEndian.Uint64(header[5:13]), nil
}
