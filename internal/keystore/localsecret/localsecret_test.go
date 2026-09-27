package localsecret

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestLoadOrCreateWritesOwnerOnlySecretAndReusesIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keeper")
	t.Setenv(DirEnvVar, dir)
	first, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.root) != secretBytes {
		t.Fatalf("secret length = %d", len(first.root))
	}
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.root, second.root) {
		t.Fatal("Load returned a different secret than LoadOrCreate wrote")
	}
	if runtime.GOOS == "windows" {
		return
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, fileName): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
}

func TestLoadFailsClosedWithoutSecret(t *testing.T) {
	t.Setenv(DirEnvVar, filepath.Join(t.TempDir(), "missing"))
	if _, err := Load(); err == nil {
		t.Fatal("Load succeeded without a secret file")
	}
}

func TestLoadRefusesSecretOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply")
	}
	dir := filepath.Join(t.TempDir(), "keeper")
	t.Setenv(DirEnvVar, dir)
	if _, err := LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, fileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted a world-readable secret")
	}
	if err := os.Chmod(filepath.Join(dir, fileName), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted a secret inside a directory others can list")
	}
}

func TestConcurrentCreatorsAgreeOnOneSecret(t *testing.T) {
	t.Setenv(DirEnvVar, filepath.Join(t.TempDir(), "keeper"))
	const workers = 8
	results := make([][]byte, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret, err := LoadOrCreate()
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = secret.root
		}()
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if !bytes.Equal(results[0], results[i]) {
			t.Fatal("concurrent creators produced different secrets")
		}
	}
}

func TestDerivedKeysAreSeparated(t *testing.T) {
	secret := Secret{root: bytes.Repeat([]byte{7}, secretBytes)}
	if bytes.Equal(secret.AppPairingKey(), secret.NativeProxyKey()) {
		t.Fatal("App pairing key and native proxy key must differ")
	}
	if bytes.Equal(secret.AppPairingKey(), secret.root) {
		t.Fatal("App pairing key must not be the root secret")
	}
}
