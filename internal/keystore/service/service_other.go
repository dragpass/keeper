//go:build !darwin && !linux && !windows

package service

import "errors"

func manageDarwin(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageLinux(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}

func manageWindows(string, string) error {
	return errors.New("Keeper App service lifecycle is not supported on this operating system")
}
