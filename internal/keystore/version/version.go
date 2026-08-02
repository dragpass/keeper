// Package version exposes the keeper binary version constant and the
// SHA-256 / absolute-path of the running keeper binary.
//
// LoadBinaryInfo() must be called once at startup (main.go) so that
// HandlePing can echo BinaryHash and BinaryPath back to the Extension.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Version must match the vX.Y.Z release tag. CI enforces this invariant.
const Version = "0.0.22"

var (
	BinaryHash string
	BinaryPath string
)

func LoadBinaryInfo() error {
	var err error
	BinaryPath, err = os.Executable()
	if err != nil {
		return err
	}

	file, err := os.Open(BinaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	BinaryHash = hex.EncodeToString(hasher.Sum(nil))

	return nil
}
