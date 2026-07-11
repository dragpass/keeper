// Package version exposes the keeper binary version constant and the
// SHA-256 / absolute-path of the running keeper binary.
//
// LoadBinaryInfo() must be called once at startup (main.go) so that
// HandlePing can echo BinaryHash and BinaryPath back to the Extension.
//
// Extracted from internal/keystore/version.go into its own subpackage.
// Backward-compat aliases live in internal/keystore/version_aliases.go.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Version 은 공개 repo (github.com/dragpass/keeper) 이관 시점에 0.0.1 로
// 리셋했다 (구 내부 넘버링 마지막은 0.0.23). 릴리스 태그 vX.Y.Z 와 반드시
// 일치해야 한다 — release CI 의 verify job 이 강제한다.
const Version = "0.0.3"

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
