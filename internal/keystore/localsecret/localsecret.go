// Package localsecret holds the per-user secret that authenticates the local
// Keeper channels. The loopback port is shared by every OS user on a machine,
// so the Origin header and the port alone cannot tell a same-user caller from
// another user's process. Only a caller that can read this owner-only file (or
// an App that was paired with a key derived from it) can drive the owner.
package localsecret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DirEnvVar overrides the directory, like KEEPER_CHAT_STATE_DIR, so tests
	// and e2e runs stay off the developer's own secret.
	DirEnvVar   = "DRAGPASS_KEEPER_LOCAL_DIR"
	fileName    = "local-rpc.key"
	secretBytes = 32
)

type Secret struct {
	root []byte
}

// AppPairingKey is the only value the App receives. Deriving it keeps a
// leaked browser copy from also opening the native proxy channel.
func (s Secret) AppPairingKey() []byte { return s.derive("dragpass-keeper-app-pairing-v1") }

func (s Secret) NativeProxyKey() []byte { return s.derive("dragpass-keeper-native-proxy-v1") }

func (s Secret) derive(label string) []byte {
	mac := hmac.New(sha256.New, s.root)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func Dir() (string, error) {
	if override := os.Getenv(DirEnvVar); override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve Keeper local secret directory: %w", err)
	}
	return filepath.Join(dir, "dragpass-keeper", "local-rpc"), nil
}

// Load reads an existing secret. A missing or loosely permissioned file is an
// error: the caller must not fall back to talking without authentication.
func Load() (Secret, error) {
	dir, err := Dir()
	if err != nil {
		return Secret{}, err
	}
	if err := checkPrivate(dir, true); err != nil {
		return Secret{}, err
	}
	path := filepath.Join(dir, fileName)
	if err := checkPrivate(path, false); err != nil {
		return Secret{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Secret{}, fmt.Errorf("read Keeper local secret: %w", err)
	}
	root, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(root) != secretBytes {
		return Secret{}, errors.New("Keeper local secret is malformed")
	}
	return Secret{root: root}, nil
}

// LoadOrCreate returns the secret, creating it on first use. The value is
// written to a temporary file and published with a hard link, which fails if
// the name exists, so racing owners never read a half-written file and all end
// up with the same value.
func LoadOrCreate() (Secret, error) {
	dir, err := Dir()
	if err != nil {
		return Secret{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Secret{}, fmt.Errorf("create Keeper local secret directory: %w", err)
	}
	if err := tightenOwnDir(dir); err != nil {
		return Secret{}, err
	}
	if secret, err := Load(); err == nil {
		return secret, nil
	}
	root := make([]byte, secretBytes)
	if _, err := rand.Read(root); err != nil {
		return Secret{}, fmt.Errorf("generate Keeper local secret: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".local-rpc-*.tmp")
	if err != nil {
		return Secret{}, fmt.Errorf("create Keeper local secret: %w", err)
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.WriteString(base64.RawURLEncoding.EncodeToString(root) + "\n")
	chmodErr := temp.Chmod(0o600)
	closeErr := temp.Close()
	if writeErr != nil || chmodErr != nil || closeErr != nil {
		return Secret{}, errors.New("write Keeper local secret")
	}
	if err := os.Link(temp.Name(), filepath.Join(dir, fileName)); err != nil && !errors.Is(err, os.ErrExist) {
		return Secret{}, fmt.Errorf("publish Keeper local secret: %w", err)
	}
	return Load()
}

// IsZero reports a Secret that was never loaded; channels refuse to start
// with it rather than derive keys from an empty root.
func (s Secret) IsZero() bool { return len(s.root) == 0 }
