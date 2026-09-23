// seal.go — the owner's seal key and the two subkeys derived from it.

package chatstate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const sealKeyBytes = 32

// Labels for the four things the seal key is used for. One key with four
// labels rather than four keyring entries: the derivation is what separates
// them, and a second entry would be a second thing to keep in step during a
// purge.
//
// **The seal key is per owner account, not per conversation, and every
// conversation of that owner is sealed under subkeys of it.** So there is no
// such thing as deleting one conversation by deleting a key: removing this key
// makes every one of that account's conversations unopenable at once. A
// per-conversation erasure has to be a record deletion, and `chat_state_purge`
// is deliberately owner-scoped for the same reason — its request carries an
// owner account id and nothing narrower.
//
// **And deleting the key is not an erasure while a copy of it survives.** It is
// removed from this keyring; a keychain backup, a synced keychain, or a
// mirrored test store that still holds the value can open every record file
// that was kept alongside it.
const (
	nameSubkeyLabel = "dragpass.chat.state.name|1"
	aeadSubkeyLabel = "dragpass.chat.state.aead|1"

	// historySubkeyLabel seals the local copies of delivered messages. Design
	// §8.4 requires that key to be something other than an MLS message key,
	// which a subkey of this master is. Whether it should be its own keyring
	// secret, so that the history can be destroyed without the state, is
	// M4.6.3 and is not decided here.
	historySubkeyLabel = "dragpass.chat.state.history|1"

	// keyPackagePoolSubkeyLabel seals the private keys of this owner's
	// outstanding KeyPackages (key_package_pool.go).
	keyPackagePoolSubkeyLabel = "dragpass.chat.state.keypackages|1"
)

// ownerTagDomain separates the keyless owner tag from anything else that might
// one day hash an account id.
const ownerTagDomain = "dragpass.chat.state.owner|1|"

var errSealKeyMalformed = errors.New("chat state seal key is malformed")

func sealKeyAccount(ownerAccountID string) string {
	return sealKeyAccountForTag(ownerTag(ownerAccountID))
}

func sealKeyAccountForTag(tag string) string {
	return config.ChatStateSealKeyPrefix + tag
}

func loadSealKey(secrets keychain.SecretStore, ownerAccountID string) ([]byte, error) {
	value, err := secrets.Get(config.Service, sealKeyAccount(ownerAccountID))
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != sealKeyBytes {
		return nil, errSealKeyMalformed
	}
	return key, nil
}

// createSealKey mints the owner's seal key under a lock and re-checks first.
// Three Keeper processes can be spawned at once and all three can find the slot
// empty; without the lock they would each mint a key and each seal files the
// other two cannot open.
func createSealKey(secrets keychain.SecretStore, root, ownerAccountID string) ([]byte, error) {
	// The owner's directory is created with the key, before any conversation
	// needs it, so that a seal key always has a directory. A device reset finds
	// owners by listing directories; a key with none would outlive the reset
	// that is supposed to take it.
	if err := ensureOwnerOnlyDir(root, filepath.Join(root, ownerTag(ownerAccountID))); err != nil {
		return nil, err
	}
	release, err := acquireConversationLock(filepath.Join(root, "seal"+lockSuffix), LockTimeout)
	if err != nil {
		return nil, err
	}
	defer release()

	if key, err := loadSealKey(secrets, ownerAccountID); err == nil {
		return key, nil
	} else if !errors.Is(err, keychain.ErrSecretNotFound) {
		return nil, err
	}

	key := make([]byte, sealKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := secrets.Set(
		config.Service, sealKeyAccount(ownerAccountID), base64.StdEncoding.EncodeToString(key),
	); err != nil {
		secure.Zeroize(key)
		return nil, fmt.Errorf("store chat state seal key: %w", err)
	}
	return key, nil
}

func deriveSubkey(master []byte, label string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// conversationTag names a conversation's file and its anchor slot. Keyed by the
// name subkey rather than a bare hash so the directory listing and the keyring
// slot names carry no conversation id. The same user account can read the key,
// so this is metadata hygiene, not a boundary, and is not claimed as one.
func (s *Store) conversationTag(conversationID string) string {
	mac := hmac.New(sha256.New, s.nameKey)
	mac.Write([]byte("conversation|" + s.owner + "|" + conversationID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// ownerTag names one owner's directory and their seal key slot. Unlike
// conversationTag it is keyed by nothing, and that is what a device reset
// depends on: it enumerates the directories under the state root and has to
// name the seal key slot of each one, without having been told which accounts
// exist — SecretStore offers Get / Set / Delete and no listing, and the action
// a user reaches for when the server-side account is gone has no account id to
// pass. A keyed tag would make those slots unreachable from that sweep. The
// hygiene is unchanged: neither form can be walked back to an account id, and
// both are visible only to the user who can already read the keyring.
func ownerTag(ownerAccountID string) string {
	sum := sha256.Sum256([]byte(ownerTagDomain + ownerAccountID))
	return hex.EncodeToString(sum[:16])
}
