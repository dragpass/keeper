package service

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/keytransparency"
)

func Manage(action, executable string) error {
	if action != "install" && action != "uninstall" {
		return errors.New("usage: dragpass-keeper service install|uninstall")
	}
	if action == "install" {
		if _, err := configuredTrustFile(); err != nil {
			return err
		}
	}
	switch runtime.GOOS {
	case "darwin":
		return manageDarwin(action, executable)
	case "linux":
		return manageLinux(action, executable)
	case "windows":
		return manageWindows(action, executable)
	default:
		return errors.New("Keeper App service lifecycle is not supported on this operating system")
	}
}

func configuredTrustFile() (string, error) {
	path := strings.TrimSpace(os.Getenv(keytransparency.TrustConfigEnv))
	if path == "" {
		return "", nil
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("could not resolve the Key Transparency trust file")
	}
	info, err := os.Stat(absolutePath)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("Key Transparency trust file is not a readable regular file")
	}
	if err := keytransparency.LoadGateFromEnv().ConfigErr; err != nil {
		return "", errors.New("Key Transparency trust file is invalid")
	}
	return absolutePath, nil
}
