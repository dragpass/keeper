package keychain

// archive_session_index.go — the organizations that may hold a
// recovery-session slot (lv90 K0 with lv100 F1).
//
// The session slot is per organization (OrgArchiveSessionPrivateKeyPrefix +
// org_id), and SecretStore has Get / Set / Delete but no listing, so the
// startup sweep finds the slots through this index:
//
//	org_archive_session_index → {"v":1,"orgs":["<org_id>", ...]}
//
// Entries identify organization slots and supplementary slots, never key material. archive_session_begin
// adds the organization before it writes the slot, so a slot is never left
// without an entry; a deleted slot removes its entry afterwards, and an entry
// whose slot is gone is dropped by the next sweep. Callers hold the keychain
// process lock (WithKeychainProcessLock) around every read-modify-write.
//
// The index only lets the startup sweep reach every slot. Security does not
// depend on it: every use reads the slot's own expiry and refuses an expired
// one whether or not a sweep ever ran.

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/dragpass/keeper/config"
)

// ArchiveSessionIndexVersion is the schema version of the index record.
const ArchiveSessionIndexVersion = 1

// ErrArchiveSessionIndexUnreadable is returned for an index Keeper cannot
// parse or whose version it does not know.
var ErrArchiveSessionIndexUnreadable = errors.New("archive session index unreadable")

type archiveSessionIndex struct {
	V    int      `json:"v"`
	Orgs []string `json:"orgs"`
}

// Page zero keeps the original v1 name and encoding. Numbered overflow pages
// stay contiguous, including empty interior pages, so no manifest is needed.
func archiveSessionIndexKey(page int) string {
	if page == 0 {
		return config.OrgArchiveSessionIndex
	}
	return config.OrgArchiveSessionIndex + ":" + strconv.Itoa(page)
}

func readArchiveSessionPages(store SecretStore) ([][]string, error) {
	var pages [][]string
	var legacyErr error
	for page := 0; ; page++ {
		raw, err := store.Get(config.Service, archiveSessionIndexKey(page))
		if errors.Is(err, ErrSecretNotFound) || (page == 0 && err == nil && raw == "") {
			if page == 0 {
				// An older Keeper can delete the legacy item while overflow exists.
				pages = append(pages, nil)
				continue
			}
			return pages, legacyErr
		}
		if err != nil {
			return nil, err
		}
		var index archiveSessionIndex
		if json.Unmarshal([]byte(raw), &index) != nil || index.V != ArchiveSessionIndexVersion {
			if page != 0 {
				return nil, ErrArchiveSessionIndexUnreadable
			}
			// Validate all overflow before allowing begin to repair the legacy item.
			legacyErr = ErrArchiveSessionIndexUnreadable
			pages = append(pages, nil)
			continue
		}
		pages = append(pages, index.Orgs)
	}
}

// ListArchiveSessionOrgs returns a slot only once, even if an older Keeper
// added it to the legacy page without seeing its overflow entry.
func ListArchiveSessionOrgs(store SecretStore) ([]string, error) {
	pages, err := readArchiveSessionPages(store)
	if err != nil {
		return nil, err
	}
	var orgs []string
	seen := make(map[string]bool)
	for _, page := range pages {
		for _, org := range page {
			if !seen[org] {
				orgs = append(orgs, org)
				seen[org] = true
			}
		}
	}
	return orgs, nil
}

func encodeArchiveSessionPage(orgs []string) ([]byte, error) {
	return json.Marshal(archiveSessionIndex{V: ArchiveSessionIndexVersion, Orgs: orgs})
}

// AddArchiveSessionOrg writes one item before the caller stores the slot.
func AddArchiveSessionOrg(store SecretStore, orgID string) error {
	pages, err := readArchiveSessionPages(store)
	if err != nil {
		// Begin has historically replaced an unreadable legacy index. A
		// damaged overflow page must never cause a healthy root to be replaced.
		if !errors.Is(err, ErrArchiveSessionIndexUnreadable) || pages == nil {
			return err
		}
		pages = [][]string{nil}
	}
	for _, orgs := range pages {
		if slices.Contains(orgs, orgID) {
			return nil
		}
	}
	for page, orgs := range append(pages, nil) {
		data, err := encodeArchiveSessionPage(append(orgs, orgID))
		if err != nil {
			return err
		}
		if len(data) <= ItemValueLimit {
			return store.Set(config.Service, archiveSessionIndexKey(page), string(data))
		}
	}
	return errors.New("archive session index entry exceeds the platform item limit")
}

// RemoveArchiveSessionOrg preserves the path to every later page. A partially
// completed removal of duplicate entries can be retried.
func RemoveArchiveSessionOrg(store SecretStore, orgID string) error {
	pages, err := readArchiveSessionPages(store)
	if err != nil {
		return err
	}
	for page, orgs := range pages {
		kept := slices.DeleteFunc(orgs, func(org string) bool { return org == orgID })
		if len(kept) == len(orgs) {
			continue
		}
		key := archiveSessionIndexKey(page)
		if len(kept) == 0 && page == len(pages)-1 {
			if err := store.Delete(config.Service, key); err != nil && !errors.Is(err, ErrSecretNotFound) {
				return err
			}
			continue
		}
		data, err := encodeArchiveSessionPage(kept)
		if err != nil {
			return err
		}
		if err := store.Set(config.Service, key, string(data)); err != nil {
			return err
		}
	}
	return nil
}
