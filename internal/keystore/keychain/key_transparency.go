package keychain

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

type KeyTransparencyCheckpoint struct {
	Version int    `json:"version"`
	Origin  string `json:"origin"`
	Size    uint64 `json:"size"`
	Root    []byte `json:"root"`
}

func GetKeyTransparencyCheckpoint(store SecretStore) (KeyTransparencyCheckpoint, bool, error) {
	raw, err := store.Get(config.Service, config.KeyTransparencyAnchorAccount)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return KeyTransparencyCheckpoint{}, false, nil
		}
		return KeyTransparencyCheckpoint{}, false, err
	}
	var anchor KeyTransparencyCheckpoint
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&anchor); err != nil || anchor.Version != 1 || anchor.Origin == "" || anchor.Size == 0 || len(anchor.Root) != 32 {
		return KeyTransparencyCheckpoint{}, false, errors.New("key transparency checkpoint anchor is malformed")
	}
	return anchor, true, nil
}

func SaveKeyTransparencyCheckpoint(store SecretStore, next KeyTransparencyCheckpoint) error {
	if next.Version != 1 || next.Origin == "" || next.Size == 0 || len(next.Root) != 32 {
		return errors.New("key transparency checkpoint anchor is malformed")
	}
	return WithKeychainProcessLock(store, func() error {
		current, exists, err := GetKeyTransparencyCheckpoint(store)
		if err != nil {
			return err
		}
		if exists {
			if current.Origin != next.Origin || next.Size < current.Size {
				return errors.New("key transparency checkpoint anchor cannot move backwards")
			}
			if next.Size == current.Size && !bytes.Equal(next.Root, current.Root) {
				return errors.New("key transparency checkpoint conflicts with stored anchor")
			}
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return err
		}
		return store.Set(config.Service, config.KeyTransparencyAnchorAccount, string(encoded))
	})
}

func UpdateKeyTransparencyCheckpoint(
	store SecretStore,
	transition func(*KeyTransparencyCheckpoint) (KeyTransparencyCheckpoint, error),
) error {
	if transition == nil {
		return errors.New("key transparency checkpoint transition is required")
	}
	return WithKeychainProcessLock(store, func() error {
		current, exists, err := GetKeyTransparencyCheckpoint(store)
		if err != nil {
			return err
		}
		var currentPtr *KeyTransparencyCheckpoint
		if exists {
			currentPtr = &current
		}
		next, err := transition(currentPtr)
		if err != nil {
			return err
		}
		if next.Version != 1 || next.Origin == "" || next.Size == 0 || len(next.Root) != 32 {
			return errors.New("key transparency checkpoint anchor is malformed")
		}
		if exists {
			if current.Origin != next.Origin || next.Size < current.Size {
				return errors.New("key transparency checkpoint anchor cannot move backwards")
			}
			if next.Size == current.Size && !bytes.Equal(next.Root, current.Root) {
				return errors.New("key transparency checkpoint conflicts with stored anchor")
			}
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return err
		}
		return store.Set(config.Service, config.KeyTransparencyAnchorAccount, string(encoded))
	})
}
