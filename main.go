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
	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/localrpc"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proc"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/service"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// Items stored in the keystore:
// - Server public key (saved on init)
// - device key
// - session code
// - Keeper private key
// - Keeper public key

// API Actions:
// (ping) health check
// (deletedevicekey) delete device key request
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
	// An unusable trust file does not stop the process: the extension would
	// only see a dead host. The Keeper keeps running and refuses every key
	// change with key_transparency_trust_invalid instead.
	deps := keystore.Deps{KeyTransparency: keytransparency.LoadGateFromEnv()}
	// Nil unless this is a keeper_e2e build running in E2E mode (e2e_mode.go).
	finishE2E := configureE2E(&deps)
	app := keystore.NewApp(deps)
	if finishE2E != nil {
		finishE2E(app)
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
	if err := refuseE2EEnvironment(os.Environ()); err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		printVersion(os.Stdout)
		return
	}
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
	address, err := localrpc.Address(e2eModeEnabled(os.Getenv) && os.Getenv(localsecret.DirEnvVar) != "", os.Getenv)
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
	// explicitly. Started identically in a keeper_e2e build — keeps flow
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
	return !e2eModeEnabled(getenv) || getenv(localsecret.DirEnvVar) != ""
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
		secure.Zeroize(msg)

		// Send response
		if err := msgr.SendResponse(resp); err != nil {
			logger.Printf("Failed to send response: %v", err)
			break
		}
	}
}
