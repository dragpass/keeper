package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func TestLoadBinaryInfo(t *testing.T) {
	BinaryHash = ""
	BinaryPath = ""

	err := LoadBinaryInfo()
	if err != nil {
		t.Fatalf("LoadBinaryInfo() failed with error: %v", err)
	}

	if BinaryPath == "" {
		t.Errorf("BinaryPath should not be empty")
	}
	if BinaryHash == "" {
		t.Errorf("BinaryHash should not be empty")
	}

	expectedPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path for verification: %v", err)
	}

	if BinaryPath != expectedPath {
		t.Errorf("BinaryPath mismatch: got %s, want %s", BinaryPath, expectedPath)
	}

	file, err := os.Open(expectedPath)
	if err != nil {
		t.Fatalf("Failed to open binary file for verification: %v", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatalf("Failed to hash binary file for verification: %v", err)
	}
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	if BinaryHash != expectedHash {
		t.Errorf("BinaryHash mismatch: got %s, want %s", BinaryHash, expectedHash)
	} else {
		t.Logf("BinaryHash correctly computed: %s", BinaryHash)
	}
}
