package main

import (
	"io"
	"log"
	"os"

	"github.com/awnumar/memguard"
	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proc"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
	"github.com/zalando/go-keyring"
)

// e2eMode makes the keeper use an in-memory MockKeyring instead of the
// Keychain. Activated by setting the KEEPER_E2E_MODE=1 env var. When active:
//   - All keyring.Set/Get/Delete operate on a process-local map
//   - The user's OS Keychain entries are unaffected
//   - All keys are lost on process exit (suitable for test isolation)
//
// Must never be enabled in production. Fixtures inject the env var explicitly.
const e2eEnvVar = "KEEPER_E2E_MODE"
const e2eUserPresenceFileEnvVar = "KEEPER_E2E_USER_PRESENCE_FILE"

// Items stored in the keystore:
// - Server public key (saved on init)
// - device key
// - session code
// - Keeper private key
// - Keeper public key

// API Actions:
// (ping) health check
// (savedevicekey) save device key request
// (deletedevicekey) delete device key request
// (getdevicekey) fetch device key request
// (generatekeypair) generate keypair request [Internal: delete session code, delete existing keypair, save new keypair]
// (getsessioncode) fetch session code request
// (getpublickey) fetch Keeper public key request

// Signup:
// (signalias) pass Alias -> generate Signature over Alias with Helper private key -> return Signature, Helper public key
// (savesessioncode) encrypted session code, Signature -> verify Signature with server public key, decrypt with Helper private key, save session code -> return session code

// Login:
// (signaliaswithtimestamp) pass Alias -> generate Signature over Alias + Timestamp with Helper private key (signing) -> return Signature, Timestamp
// (signchallengetoken) pass Signature, ChallengeToken -> verify Signature with server public key, sign challenge token with Helper private key -> return Signature

// Login on a different device:
// (generatekeypair) pass Signature, ChallengeToken -> verify Signature with server public key, generate keypair -> return Public Key
// (getpublickey) fetch Keeper public key
// (savesessioncode) save encrypted session code

// Logging policy:
//
//   - For fatal failures just before init() / main() start, use stdlib
//     `log.Fatalf` — the Logger interface has no Fatalf, and log.Fatalf
//     writes to stderr and calls os.Exit(1), which is suitable as a process
//     boot failure signal.
//   - All other informational / warning logs in the normal flow pass through
//     an explicitly constructed App.Logger — unit tests can capture them by
//     injecting MemoryLogger, and a future swap to a structured logger
//     (zerolog, etc.) changes only one place.

func init() {
	userpresence.PrepareProcessMainThread()
	deps := keystore.Deps{UserPresence: userpresence.NewPlatform()}
	// e2e mode: use an in-memory mock instead of the Keychain. Must be
	// called before EnsureServerPublicKey (so that the server pubkey is
	// saved into the mock).
	if os.Getenv(e2eEnvVar) == "1" {
		keyring.MockInit()
		// In E2E mode, use the in-memory MemoryClipboard instead of the OS
		// clipboard. User clipboard is unaffected, and the
		// clipboard_get_last_hash action can query the SHA-256 hash.
		// SetDefaultDeps must run before the first DefaultApp() call.
		deps.Clipboard = clipboard.NewMemoryClipboard()
		if path := os.Getenv(e2eUserPresenceFileEnvVar); path != "" {
			deps.UserPresence = userpresence.NewE2EFile(path)
		} else {
			deps.UserPresence = userpresence.Unavailable{}
		}
		keystore.SetDefaultDeps(deps)
		app := keystore.DefaultApp()
		app.Logger.Println("KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)")
		app.Logger.Println("KEEPER_E2E_MODE=1: using MemoryClipboard (no OS clipboard access)")

		// Optional: if KEEPER_E2E_KEYRING_FILE is set, load the file into
		// the mock. Used so fixtures can share keyring entries between the
		// popup process and the SW process. See internal/keystore/krfile.go
		// comments for details.
		if filePath := os.Getenv("KEEPER_E2E_KEYRING_FILE"); filePath != "" {
			if err := keystore.LoadE2EKeyringFile(filePath); err != nil {
				app.Logger.Printf("KEEPER_E2E_KEYRING_FILE load failed (continuing): %v", err)
			} else {
				app.Logger.Printf("KEEPER_E2E_KEYRING_FILE=%s loaded into mock keyring", filePath)
			}
		}
	}
	if os.Getenv(e2eEnvVar) != "1" {
		keystore.SetDefaultDeps(deps)
	}

	app := keystore.DefaultApp()
	if err := keychain.EnsureServerPublicKey(app.Store, app.Logger); err != nil {
		log.Fatalf("Critical: Failed to ensure server public key: %v", err)
	}
}

func main() {
	// Protect all memguard-managed memory; purge on exit
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Stdout is sent to the Chrome extension, so we log to Stderr
	log.SetOutput(os.Stderr)

	app := keystore.DefaultApp()
	logger := app.Logger

	// Process hardening — disable core dumps. Closes the surface where
	// plaintext could be exposed in a disk core file. Failure is not fatal.
	if err := proc.DisableCoreDumps(); err != nil {
		logger.Printf("Warning: Failed to disable core dumps: %v", err)
	}

	if err := keystore.LoadBinaryInfo(); err != nil {
		logger.Printf("Warning: Failed to calculate binary info: %v", err)
	}

	if err := keychain.EnsureServerPublicKey(app.Store, app.Logger); err != nil {
		log.Fatalf("Critical: Failed to ensure server public key: %v", err)
	}

	// Group DEK opaque handle reaper. Sweeps every 1 minute and destroys
	// LockedBuffers, even for handles that the Extension forgot to close
	// explicitly. Started identically in tests (KEEPER_E2E_MODE) — keeps flow
	// consistent with production.
	keystore.StartDefaultGroupSessionReaper()

	// Recovery PEM opaque handle reaper.
	keystore.StartDefaultRecoverySessionReaper()
	keystore.StartDefaultRecoveryKeySessionReaper()

	logger.Println("DragPass extension helper started")
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("Critical Panic Recovered: %v", r)
		}
	}()

	runHost := func() {
		runMessageLoop(app)
	}
	if app.UserPresence.Capabilities().Available {
		userpresence.RunHost(runHost)
		return
	}
	runHost()
}

func runMessageLoop(app *keystore.App) {
	logger := app.Logger
	msgr := app.NewMessenger(os.Stdin, os.Stdout)
	for {

		// Read raw message bytes
		msg, err := msgr.ReadMessage()
		if err != nil {
			if err == io.EOF {
				logger.Println("Chrome extension closed the connection")
				break
			}
			logger.Printf("Failed to read message: %v", err)

			errorResponse := keystore.BaseResponse{
				Success: false,
				Error:   "Native host read error: " + err.Error(),
			}

			if sendErr := msgr.SendResponse(errorResponse); sendErr != nil {
				logger.Printf("Failed to send error response: %v", sendErr)
				break
			}
			continue
		}

		// Handle the request
		resp := app.HandleRequest(msg)

		// Send response
		if err := msgr.SendResponse(resp); err != nil {
			logger.Printf("Failed to send response: %v", err)
			break
		}
	}
}
