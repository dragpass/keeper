package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/awnumar/memguard"
	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/localrpc"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proc"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/service"
	"github.com/dragpass/keeper/internal/keystore/sessions"
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

// Items stored in the keystore:
// - Server public key (saved on init)
// - device key
// - session code
// - Keeper private key
// - Keeper public key

// API Actions:
// (ping) health check
// (savedevicekey) save device key request (deprecated)
// (deletedevicekey) delete device key request
// (getdevicekey) fetch device key request (deprecated)
// (device_key_status) report whether a device key is stored
// (device_key_ensure) generate and store a device key inside Keeper when absent
// (generatekeypair) generate keypair request [Internal: delete session code, delete existing keypair, save new keypair]
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

func newProcessApp() *keystore.App {
	var app *keystore.App
	// An unusable trust file does not stop the process: the extension would
	// only see a dead host. The Keeper keeps running and refuses every key
	// change with key_transparency_trust_invalid instead.
	deps := keystore.Deps{KeyTransparency: keytransparency.LoadGateFromEnv()}
	// e2e mode: use an in-memory mock instead of the Keychain. Must be
	// called before EnsureServerPublicKey (so that the server pubkey is
	// saved into the mock).
	if os.Getenv(e2eEnvVar) == "1" {
		keyring.MockInit()
		// In E2E mode, use the in-memory MemoryClipboard instead of the OS
		// clipboard. User clipboard is unaffected, and the
		// clipboard_get_last_hash action can query the SHA-256 hash.
		//
		// KEEPER_E2E_OS_CLIPBOARD=1 opts back into the real OS clipboard for
		// the marketing hero recorder, which needs the content script's
		// navigator.clipboard.readText() to see the decrypted plaintext.
		// The env var is read only inside this branch, so it is structurally
		// a no-op in production. See clipboard/sink.go.
		sink := clipboard.SelectSink(true, os.Getenv(clipboard.E2EOSClipboardEnvVar) == "1")
		if sink == clipboard.SinkOS {
			deps.Clipboard = clipboard.NewProductionClipboard()
		} else {
			deps.Clipboard = clipboard.NewMemoryClipboard()
		}
		app = keystore.NewApp(deps)
		app.Logger.Println("KEEPER_E2E_MODE=1: using in-memory keyring (no OS Keychain access)")
		if sink == clipboard.SinkOS {
			app.Logger.Println("KEEPER_E2E_OS_CLIPBOARD=1: using the real OS clipboard (recording opt-in; clipboard_get_last_hash unavailable)")
		} else {
			app.Logger.Println("KEEPER_E2E_MODE=1: using MemoryClipboard (no OS clipboard access)")
		}

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
		app = keystore.NewApp(deps)
	}
	if err := deps.KeyTransparency.ConfigErr; err != nil {
		app.Logger.Printf("key transparency is required but unusable; key changes are refused: %v", err)
	}

	if err := keychain.EnsureServerPublicKey(app.Store, app.Logger); err != nil {
		log.Fatalf("Critical: Failed to ensure server public key: %v", err)
	}
	return app
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "service" {
		executable, err := os.Executable()
		if err != nil {
			log.Fatal("Could not locate the Keeper executable")
		}
		if err := service.Manage(os.Args[2], executable); err != nil {
			log.Fatal(err)
		}
		if os.Args[2] == "install" {
			// The service serves only a paired App, so installing it opens
			// the pairing page right away.
			if err := pairApp(defaultAppOrigin, true, os.Stdout); err != nil {
				log.Printf("The service is installed but the pairing page could not be prepared: %v. Run `dragpass-keeper app pair`.", err)
			}
		}
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == "app" {
		if err := runAppCommand(os.Args[2:], os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	appService := flag.Bool("app-service", false, "run the local App RPC service")
	trustFile := flag.String("key-transparency-trust-file", "", "load Key Transparency trust configuration from this file")
	flag.Parse()
	if *trustFile != "" {
		if err := os.Setenv(keytransparency.TrustConfigEnv, *trustFile); err != nil {
			log.Fatal("Could not configure Key Transparency trust file")
		}
	}

	// Protect all memguard-managed memory; purge on exit
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Stdout is sent to the Chrome extension, so we log to Stderr
	log.SetOutput(os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var listener net.Listener
	var secret localsecret.Secret
	address, err := localrpc.Address(os.Getenv(e2eEnvVar) == "1" && os.Getenv(localsecret.DirEnvVar) != "", os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if *appService {
		if !localRPCEnabled(os.Getenv) {
			log.Fatal("An e2e Keeper runs the App service only with an isolated local secret directory")
		}
		secret, err = localsecret.LoadOrCreate()
		if err != nil {
			log.Fatalf("Local Keeper service could not load its local secret: %v", err)
		}
		listener, err = localrpc.AcquireAppServiceOwner(ctx, address)
		if err != nil {
			log.Fatalf("Local Keeper service could not claim its address: %v", err)
		}
	} else {
		role := localrpc.RoleStandalone
		var proxy *localrpc.NativeProxy
		var loaded localsecret.Secret
		err := errors.New("e2e mode without an isolated local secret directory")
		if localRPCEnabled(os.Getenv) {
			loaded, err = localsecret.LoadOrCreate()
		}
		if err != nil {
			// Without the secret neither local channel can be authenticated, so
			// this host serves its own stdio only, as before the shared owner.
			log.Printf("Keeper local secret unavailable, running standalone: %v", err)
		} else {
			secret = loaded
			role, listener, proxy, err = localrpc.AcquireNativeOwner(address, secret)
			if err != nil {
				log.Fatal("Local Keeper owner could not be established")
			}
		}
		if role == localrpc.RoleProxy {
			runNativeProxyMessageLoop(proxy)
			return
		}
		if role == localrpc.RoleStandalone {
			log.Printf("Keeper local address is held by an owner that could not be proven; running standalone")
		}
	}
	if err := proc.DisableCoreDumps(); err != nil {
		log.Printf("Warning: Failed to disable core dumps: %v", err)
	}

	app := newProcessApp()
	logger := app.Logger

	if err := keystore.LoadBinaryInfo(); err != nil {
		logger.Printf("Warning: Failed to calculate binary info: %v", err)
	}

	// Group DEK opaque handle reaper. Sweeps every 1 minute and destroys
	// LockedBuffers, even for handles that the Extension forgot to close
	// explicitly. Started identically in tests (KEEPER_E2E_MODE) — keeps flow
	// consistent with production.
	app.GroupSessions.StartReaper(sessions.GroupSessionReaperInterval)

	// Recovery PEM opaque handle reaper.
	app.RecoverySessions.StartReaper(sessions.RecoverySessionReaperInterval)
	app.RecoveryKeySessions.StartReaper(sessions.RecoveryKeySessionReaperInterval)

	logger.Println("DragPass Keeper started")
	logMLSLibrary(app)
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("Critical Panic Recovered: %v", r)
		}
	}()
	if listener != nil {
		service, err := localrpc.New(app, localrpc.AppOrigins(os.Getenv), secret)
		if err != nil {
			log.Fatalf("Critical: Failed to configure App RPC: %v", err)
		}
		go func() {
			if err := service.ServeListener(ctx, listener); err != nil {
				logger.Printf("App RPC stopped: %v", err)
			}
		}()
		logger.Printf("Keeper App RPC listening on %s", address)
	}
	if *appService {
		<-ctx.Done()
		return
	}

	runMessageLoop(app)
	stop()
}

// localRPCEnabled keeps an e2e Keeper (mock keyring) off the shared loopback
// address unless the test isolated the local secret: otherwise it could proxy
// its traffic to a developer's real Keeper and real Keychain.
func localRPCEnabled(getenv func(string) string) bool {
	return getenv(e2eEnvVar) != "1" || getenv(localsecret.DirEnvVar) != ""
}

func runNativeProxyMessageLoop(proxy *localrpc.NativeProxy) {
	msgr := dispatch.NewMessenger(os.Stdin, os.Stdout, nil)
	for {
		message, err := msgr.ReadMessage()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("Native Messaging proxy could not read a request: %v", err)
			return
		}
		response, err := proxy.Forward(message)
		if err != nil {
			response = proto.BaseResponse{Success: false, Error: "Keeper owner request failed"}
		}
		if err := msgr.SendResponse(response); err != nil {
			log.Printf("Native Messaging proxy could not write a response: %v", err)
			return
		}
	}
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
