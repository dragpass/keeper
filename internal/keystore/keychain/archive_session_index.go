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
// It holds organization IDs only, never key material. archive_session_begin
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

// ListArchiveSessionOrgs returns the indexed organizations. A missing index
// is an empty list.
func ListArchiveSessionOrgs(store SecretStore) ([]string, error) {
	raw, err := store.Get(config.Service, config.OrgArchiveSessionIndex)
	if errors.Is(err, ErrSecretNotFound) || (err == nil && raw == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var index archiveSessionIndex
	if json.Unmarshal([]byte(raw), &index) != nil || index.V != ArchiveSessionIndexVersion {
		return nil, ErrArchiveSessionIndexUnreadable
	}
	return index.Orgs, nil
}

// AddArchiveSessionOrg records orgID. Idempotent. An unreadable index is
// replaced by one naming orgID: the organizations it named lose only the
// startup sweep, not the refusal at use.
func AddArchiveSessionOrg(store SecretStore, orgID string) error {
	orgs, err := ListArchiveSessionOrgs(store)
	if err != nil && !errors.Is(err, ErrArchiveSessionIndexUnreadable) {
		return err
	}
	if slices.Contains(orgs, orgID) {
		return nil
	}
	return saveArchiveSessionIndex(store, append(orgs, orgID))
}

// RemoveArchiveSessionOrg drops orgID. Idempotent; an unreadable index is
// left as it is.
func RemoveArchiveSessionOrg(store SecretStore, orgID string) error {
	orgs, err := ListArchiveSessionOrgs(store)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(orgs), func(org string) bool { return org == orgID })
	if len(kept) == len(orgs) {
		return nil
	}
	if len(kept) == 0 {
		if err := store.Delete(config.Service, config.OrgArchiveSessionIndex); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
		return nil
	}
	return saveArchiveSessionIndex(store, kept)
}

func saveArchiveSessionIndex(store SecretStore, orgs []string) error {
	raw, err := json.Marshal(archiveSessionIndex{V: ArchiveSessionIndexVersion, Orgs: orgs})
	if err != nil {
		return err
	}
	return store.Set(config.Service, config.OrgArchiveSessionIndex, string(raw))
}
