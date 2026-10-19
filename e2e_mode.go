//go:build keeper_e2e

package main

import (
	"os"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/zalando/go-keyring"
)

// This file exists only in a build with the keeper_e2e tag, which the browser
// E2E harness and the real-process tests build. Release builds leave the tag
// off, so a shipped Keeper cannot be switched to the mock keyring, the keyring
// file mirror, or the memory clipboard by its environment.

// e2eEnvVar makes the keeper use an in-memory MockKeyring instead of the
// Keychain. When set to 1:
//   - All keyring.Set/Get/Delete operate on a process-local map
//   - The user's OS Keychain entries are unaffected
//   - All keys are lost on process exit (suitable for test isolation)
//
// Fixtures inject the env var explicitly.
const e2eEnvVar = "KEEPER_E2E_MODE"

func e2eModeEnabled(getenv func(string) string) bool {
	return getenv(e2eEnvVar) == "1"
}

// refuseE2EEnvironment accepts every environment: this build is the E2E one.
func refuseE2EEnvironment([]string) error { return nil }

// configureE2E swaps the keyring and clipboard in E2E mode. It must run before
// EnsureServerPublicKey so the server public key lands in the mock. The
// returned function finishes the setup once the App exists; it is nil outside
// E2E mode.
func configureE2E(deps *keystore.Deps) func(*keystore.App) {
	if !e2eModeEnabled(os.Getenv) {
		return nil
	}
	keyring.MockInit()
	// In E2E mode, use the in-memory MemoryClipboard instead of the OS
	// clipboard. User clipboard is unaffected, and the
	// clipboard_get_last_hash action can query the SHA-256 hash.
	//
	// KEEPER_E2E_OS_CLIPBOARD=1 opts back into the real OS clipboard for
	// the marketing hero recorder, which needs the content script's
	// navigator.clipboard.readText() to see the decrypted plaintext.
	// See clipboard/sink.go.
	sink := clipboard.SelectSink(true, os.Getenv(clipboard.E2EOSClipboardEnvVar) == "1")
	if sink == clipboard.SinkOS {
		deps.Clipboard = clipboard.NewProductionClipboard()
	} else {
		deps.Clipboard = clipboard.NewMemoryClipboard()
	}
	return func(app *keystore.App) {
		app.Logger.Println("KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)")
		if sink == clipboard.SinkOS {
			app.Logger.Println("KEEPER_E2E_OS_CLIPBOARD=1: using the real OS clipboard (recording opt-in; clipboard_get_last_hash unavailable)")
		} else {
			app.Logger.Println("KEEPER_E2E_MODE=1: using MemoryClipboard (no OS clipboard access)")
		}

		// Optional: if KEEPER_E2E_KEYRING_FILE is set, load the file into
		// the mock. Used so fixtures can share keyring entries between the
		// popup process and the SW process. See keychain/file_mirror.go.
		if filePath := os.Getenv("KEEPER_E2E_KEYRING_FILE"); filePath != "" {
			if err := keychain.LoadE2EKeyringFile(filePath); err != nil {
				app.Logger.Printf("KEEPER_E2E_KEYRING_FILE load failed (continuing): %v", err)
			} else {
				app.Logger.Printf("KEEPER_E2E_KEYRING_FILE=%s loaded into mock keyring", filePath)
			}
		}
	}
}
