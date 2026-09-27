//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const systemdUnitName = "dragpass-keeper-app.service"

func manageDarwin(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageWindows(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageLinux(action, executable string) error {
	currentUser, err := user.Current()
	if err != nil {
		return errors.New("could not determine the current Linux user")
	}
	uid, err := strconv.Atoi(currentUser.Uid)
	if err != nil || uid == 0 {
		return errors.New("service commands must run as a non-root user")
	}
	unitPath := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", systemdUnitName)
	if action == "uninstall" {
		if _, err := os.Stat(unitPath); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return fmt.Errorf("inspect Keeper user service: %w", err)
		}
		if output, err := exec.Command("systemctl", "--user", "disable", "--now", systemdUnitName).CombinedOutput(); err != nil {
			return fmt.Errorf("stop Keeper user service: %s", strings.TrimSpace(string(output)))
		}
		if err := os.Remove(unitPath); err != nil {
			return fmt.Errorf("remove Keeper user service: %w", err)
		}
		return runSystemctl("daemon-reload")
	}
	if !filepath.IsAbs(executable) {
		executable, err = exec.LookPath("dragpass-keeper")
		if err != nil {
			executable, err = filepath.Abs(executable)
		}
		if err != nil {
			return errors.New("could not resolve the Keeper executable path")
		}
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		return fmt.Errorf("create systemd user unit directory: %w", err)
	}
	trustFile, err := configuredTrustFile()
	if err != nil {
		return err
	}
	content := renderSystemdUnit(executable, trustFile)
	tempFile, err := os.CreateTemp(filepath.Dir(unitPath), ".keeper-service-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary Keeper unit: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		return fmt.Errorf("secure temporary Keeper unit: %w", err)
	}
	if _, err := tempFile.WriteString(content); err != nil {
		tempFile.Close()
		return fmt.Errorf("write Keeper user unit: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close Keeper user unit: %w", err)
	}
	if err := os.Rename(tempPath, unitPath); err != nil {
		return fmt.Errorf("install Keeper user unit: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if output, err := exec.Command("systemctl", "--user", "enable", "--now", systemdUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("start Keeper user service: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func runSystemctl(args ...string) error {
	commandArgs := append([]string{"--user"}, args...)
	if output, err := exec.Command("systemctl", commandArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("reload Keeper user service manager: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
