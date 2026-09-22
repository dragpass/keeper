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

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const sealKeyBytes = 32

// Labels for the two things the seal key is used for. One key with two labels
// rather than two keyring entries: the derivation is what separates them, and a
// second entry would be a second thing to keep in step during a purge.
const (
	nameSubkeyLabel = "dragpass.chat.state.name|1"
	aeadSubkeyLabel = "dragpass.chat.state.aead|1"
)

var errSealKeyMalformed = errors.New("chat state seal key is malformed")

func sealKeyAccount(ownerAccountID string) string {
	return config.ChatStateSealKeyPrefix + ownerAccountID
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

func createSealKey(secrets keychain.SecretStore, ownerAccountID string) ([]byte, error) {
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

func (s *Store) ownerTag() string {
	mac := hmac.New(sha256.New, s.nameKey)
	mac.Write([]byte("owner|" + s.owner))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
