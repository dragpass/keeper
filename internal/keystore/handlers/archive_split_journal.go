// archive_split_journal.go — the durable record of an archive split.
//
// A split result carries every wrapped share (about 2.9 KB per recipient),
// far over the smallest keychain value size the vendored go-keyring accepts
// (keychain.ItemValueLimit). The record is therefore one small manifest item
// plus the JSON encoding of the result cut into parts:
//
//	archive_quorum_split_pending:<private slot>             manifest
//	archive_quorum_split_pending:<private slot>:part:<i>    part i of n
//
// The manifest holds everything finalization, abandonment, status and the
// reconfiguration readers need (operation, request digest, key fingerprint,
// binding, state, share count, shares digest), so only a split retry reads
// the parts. A retry checks the reassembled bytes against the manifest's
// digest of the whole result encoding.

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	archiveSplitManifestVersion = 2
	// archiveSplitPartBytes is the result bytes per part. With the part
	// header (under 160 bytes) every part stays below keychain.ItemValueLimit.
	archiveSplitPartBytes = 2048
	// archiveSplitMaxParts bounds the part count read from a manifest. 255
	// recipients (the most a split request accepts) need about 360 parts.
	archiveSplitMaxParts   = 512
	archiveSplitPartDomain = "dragpass.archive.split.part|1"
)

// errArchiveSplitJournalInconsistent: a record that does not parse, does not
// match its manifest, or is incomplete. Never repaired automatically.
var errArchiveSplitJournalInconsistent = errors.New("archive split journal inconsistent")

// archiveSplitJournal is the manifest.
type archiveSplitJournal struct {
	Version        int                 `json:"v"`
	OperationID    string              `json:"operation_id"`
	RequestDigest  string              `json:"request_digest"`
	KeyFingerprint string              `json:"key_fingerprint"`
	Binding        archiveSplitBinding `json:"binding"`
	// State is empty (prepared) until finalization starts deleting.
	State        string `json:"state,omitempty"`
	ShareCount   int    `json:"share_count"`
	SharesDigest string `json:"shares_digest"`
	ResultDigest string `json:"result_digest"`
	PartCount    int    `json:"part_count"`
}

func archiveSplitJournalAccount(slot keychain.ArchiveKeySlot) string {
	return "archive_quorum_split_pending:" + slot.PrivateAccount
}

func archiveSplitPartAccount(slot keychain.ArchiveKeySlot, index int) string {
	return archiveSplitJournalAccount(slot) + ":part:" + strconv.Itoa(index)
}

// decodeArchiveSplitJournal parses a manifest; anything that is not a
// well-formed manifest is errArchiveSplitJournalInconsistent.
func decodeArchiveSplitJournal(raw string) (archiveSplitJournal, error) {
	var j archiveSplitJournal
	if json.Unmarshal([]byte(raw), &j) != nil || j.Version != archiveSplitManifestVersion {
		return archiveSplitJournal{}, errArchiveSplitJournalInconsistent
	}
	switch j.State {
	case "", archiveSplitJournalDeleting, archiveSplitJournalCleanupPending:
	default:
		return archiveSplitJournal{}, errArchiveSplitJournalInconsistent
	}
	if j.OperationID == "" || j.KeyFingerprint == "" || !isLowerHex64(j.ResultDigest) ||
		!isLowerHex64(j.SharesDigest) || j.ShareCount < 1 || j.PartCount < 1 || j.PartCount > archiveSplitMaxParts {
		return archiveSplitJournal{}, errArchiveSplitJournalInconsistent
	}
	return j, nil
}

// loadArchiveSplitJournal reads the slot's manifest. found is false when
// there is none; a storage error is returned as is, a malformed record as
// errArchiveSplitJournalInconsistent.
func loadArchiveSplitJournal(store keychain.SecretStore, slot keychain.ArchiveKeySlot) (archiveSplitJournal, bool, error) {
	raw, err := store.Get(config.Service, archiveSplitJournalAccount(slot))
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return archiveSplitJournal{}, false, nil
	}
	if err != nil {
		return archiveSplitJournal{}, false, err
	}
	j, err := decodeArchiveSplitJournal(raw)
	return j, true, err
}

func writeArchiveSplitJournal(store keychain.SecretStore, slot keychain.ArchiveKeySlot, journal archiveSplitJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return store.Set(config.Service, archiveSplitJournalAccount(slot), string(encoded))
}

func encodeArchiveSplitPart(operationID, resultDigest string, index, count int, data []byte) string {
	return archiveSplitPartDomain + "|" + operationID + "|" + resultDigest + "|" +
		strconv.Itoa(index) + "|" + strconv.Itoa(count) + "|" + string(data)
}

// recordArchiveSplitPreparation writes a new record for result: the parts,
// then the manifest. journal carries the operation, request digest, key
// fingerprint and binding.
func recordArchiveSplitPreparation(store keychain.SecretStore, slot keychain.ArchiveKeySlot, journal archiveSplitJournal, result proto.ArchiveKeySplitResponseData) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	journal.Version = archiveSplitManifestVersion
	journal.State = ""
	journal.ShareCount = len(result.Shares)
	journal.SharesDigest = proto.ArchiveSplitSharesDigest(result.Shares)
	journal.ResultDigest = hex.EncodeToString(sum[:])
	journal.PartCount = (len(encoded) + archiveSplitPartBytes - 1) / archiveSplitPartBytes
	if journal.PartCount > archiveSplitMaxParts {
		return errors.New("archive split result too large")
	}
	for i := range journal.PartCount {
		end := min((i+1)*archiveSplitPartBytes, len(encoded))
		part := encodeArchiveSplitPart(journal.OperationID, journal.ResultDigest, i, journal.PartCount, encoded[i*archiveSplitPartBytes:end])
		if err := store.Set(config.Service, archiveSplitPartAccount(slot, i), part); err != nil {
			return err
		}
	}
	return writeArchiveSplitJournal(store, slot, journal)
}

// readArchiveSplitResult reassembles a prepared record's result. A storage
// error is returned as is; any mismatch is errArchiveSplitJournalInconsistent.
func readArchiveSplitResult(store keychain.SecretStore, slot keychain.ArchiveKeySlot, journal archiveSplitJournal) (proto.ArchiveKeySplitResponseData, error) {
	var none proto.ArchiveKeySplitResponseData
	var whole strings.Builder
	for i := range journal.PartCount {
		raw, err := store.Get(config.Service, archiveSplitPartAccount(slot, i))
		if errors.Is(err, keychain.ErrSecretNotFound) {
			return none, errArchiveSplitJournalInconsistent
		}
		if err != nil {
			return none, err
		}
		fields := strings.SplitN(raw, "|", 7)
		if len(fields) != 7 {
			return none, errArchiveSplitJournalInconsistent
		}
		whole.WriteString(fields[6])
	}
	encoded := whole.String()
	sum := sha256.Sum256([]byte(encoded))
	var result proto.ArchiveKeySplitResponseData
	if hex.EncodeToString(sum[:]) != journal.ResultDigest || json.Unmarshal([]byte(encoded), &result) != nil ||
		result.KeyFingerprint != journal.KeyFingerprint || len(result.Shares) != journal.ShareCount ||
		proto.ArchiveSplitSharesDigest(result.Shares) != journal.SharesDigest {
		return none, errArchiveSplitJournalInconsistent
	}
	return result, nil
}

// deleteArchiveSplitJournal removes the manifest's parts, then the manifest.
// It reports false, with what was not deleted still in place, when any
// delete did not complete.
func deleteArchiveSplitJournal(store keychain.SecretStore, slot keychain.ArchiveKeySlot, parts int) bool {
	for i := range parts {
		if !deleteSecretGone(store, archiveSplitPartAccount(slot, i)) {
			return false
		}
	}
	return deleteSecretGone(store, archiveSplitJournalAccount(slot))
}
