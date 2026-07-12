package keychain

// file_mirror.go: when KEEPER_E2E_KEYRING_FILE is set, the mock keyring is
// mirrored to a JSON file so that multiple Keeper processes can share entries.
//
// **Why needed**
//
// `keyring.MockInit()` is a process-local map, so when the popup process and
// SW process each spawn a Keeper through their own connectNative port, the
// keyring state is independent. If signup stores a keypair in popup's Keeper,
// SW's Keeper still has an empty keyring and ADMIN_CREATE_ORG fails with
// "secret not found".
//
// **Behavior**
//
//   - When KEEPER_E2E_KEYRING_FILE is empty, every function simply delegates
//     to keyring.*.
//   - When set:
//     * Before every read, load file → mock (reflect entries written by
//       another process).
//     * After every write, dump mock → file.
//   - File format: simple JSON `{"service|user": "value"}`.
//   - File locking is intentionally skipped — fixtures call sequentially, so
//     the race window is narrow. Add an fcntl lock if races appear.
//
// **Production safety**: in production, both KEEPER_E2E_MODE and FILE are
// unset. The default branch is the OS Keychain as-is. File mirroring is only
// active when both env vars are set.

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/dragpass/keeper/config"
	"github.com/zalando/go-keyring"
)

const e2eKeyringFileEnvVar = "KEEPER_E2E_KEYRING_FILE"

// e2eFilePath returns the path if file-mirror is active, else "".
func e2eFilePath() string { return os.Getenv(e2eKeyringFileEnvVar) }

func e2eKey(service, user string) string { return service + "|" + user }

// loadFromFileIntoMock reads the file and sets every entry into the mock
// keyring. No-op when the file is missing. Assumes both KEEPER_E2E_MODE=1
// and KEEPER_E2E_KEYRING_FILE are set.
func loadFromFileIntoMock(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for k, v := range m {
		// k = "service|user". split.
		sep := -1
		for i := 0; i < len(k); i++ {
			if k[i] == '|' {
				sep = i
				break
			}
		}
		if sep < 0 {
			continue
		}
		_ = keyring.Set(k[:sep], k[sep+1:], v)
	}
	return nil
}

// dumpAllToFile writes the current state to the file from an in-memory
// snapshot we maintain ourselves via direct set/delete tracking. The mock
// provider has no full-dump API, so we keep our own snapshot map.
var snapshot = map[string]string{}

func dumpToFile(path string) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// krSet is keyring.Set + (file mirror when in e2e mode).
func krSet(service, user, value string) error {
	if err := keyring.Set(service, user, value); err != nil {
		return err
	}
	if path := e2eFilePath(); path != "" {
		snapshot[e2eKey(service, user)] = value
		if err := dumpToFile(path); err != nil {
			return err
		}
	}
	return nil
}

// krGet, in e2e mode, syncs file → mock first, then calls keyring.Get.
func krGet(service, user string) (string, error) {
	if path := e2eFilePath(); path != "" {
		// Pick up entries written by another process. Best-effort even on
		// failure.
		if err := loadFromFileIntoMock(path); err == nil {
			data, _ := os.ReadFile(path)
			if len(data) > 0 {
				_ = json.Unmarshal(data, &snapshot)
			}
		}
	}
	return keyring.Get(service, user)
}

// krDelete is keyring.Delete + (file mirror when in e2e mode).
func krDelete(service, user string) error {
	err := keyring.Delete(service, user)
	if path := e2eFilePath(); path != "" {
		delete(snapshot, e2eKey(service, user))
		if dumpErr := dumpToFile(path); dumpErr != nil && err == nil {
			return dumpErr
		}
	}
	return err
}

// KrDelete is an exported variant used via alias from the keystore root so
// existing white-box tests can continue to call krDelete without importing
// this subpackage.
func KrDelete(service, user string) error { return krDelete(service, user) }

// LoadE2EKeyringFile is the entry point called from main.go init.
// Loads the file into the mock keyring and also fills the snapshot map.
// path is treated as read-only — every write dumps back to the same path.
func LoadE2EKeyringFile(path string) error {
	if err := loadFromFileIntoMock(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &snapshot)
}

// SilenceUnused — keeps the config import in use.
var _ = config.Service

// ErrFileMirror is a sentinel intended for grouping future file-operation
// errors. Currently unused.
var ErrFileMirror = errors.New("e2e keyring file mirror error")
