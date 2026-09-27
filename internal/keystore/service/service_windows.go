//go:build windows

package service

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

const scheduledTaskName = "DragPass Keeper App Service"

func manageDarwin(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageLinux(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageWindows(action, executable string) error {
	currentUser, err := user.Current()
	if err != nil || currentUser.Uid == "" || currentUser.Username == "" {
		return errors.New("could not determine the current Windows user")
	}
	taskName := scheduledTaskName + " " + currentUser.Uid
	if action == "uninstall" {
		_ = exec.Command("schtasks.exe", "/End", "/TN", taskName).Run()
		if output, err := exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName).CombinedOutput(); err != nil {
			return fmt.Errorf("remove Keeper scheduled task: %s", strings.TrimSpace(string(output)))
		}
		return nil
	}
	if !filepath.IsAbs(executable) {
		resolved, err := exec.LookPath("dragpass-keeper.exe")
		if err != nil {
			return errors.New("could not resolve the Keeper executable path")
		}
		executable = resolved
	}
	trustFile, err := configuredTrustFile()
	if err != nil {
		return err
	}
	runCommand := renderScheduledTaskCommand(executable, trustFile)
	args := []string{
		"/Create", "/SC", "ONLOGON", "/TN", taskName,
		"/TR", runCommand, "/IT", "/RL", "LIMITED", "/F",
	}
	if output, err := exec.Command("schtasks.exe", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("install Keeper login task: %s", strings.TrimSpace(string(output)))
	}
	if output, err := exec.Command("schtasks.exe", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		_ = exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName).Run()
		return fmt.Errorf("start Keeper App service: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
