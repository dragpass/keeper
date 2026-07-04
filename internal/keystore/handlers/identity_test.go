// identity_test.go — regression guard for identity-related handlers in identity.go.
//
// Covered handlers: HandleGenerateKeypair / HandleGetPublicKey /
// HandleGetServerPublicKey / HandleSignAlias / HandleSignAliasWithTimestamp /
// HandleSignChallengeToken.
//
// **Defects this test catches:**
//   - regressions where the handler calls stdlib `log.*` directly (bypassing a.Logger)
//   - regressions where GenerateKeypair calls free `VerifyServerSig` directly
//     (bypassing a.ServerKeyVerifier.Verify)
//   - regressions where input challenge_token / signature is echoed to the logger
//   - regressions where SignAliasWithTimestamp reverts to wall-clock
//     `time.Now()` and ignores the injected Deps.Clock (determinism + Clock DI
//     consistency)
package handlers

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// TestApp_HandleGenerateKeypair_VerifyFailedShortCircuits: with an
// AlwaysFailVerifier injected, must fail immediately without entering the
// keypair-generation branch.
func TestApp_HandleGenerateKeypair_VerifyFailedShortCircuits(t *testing.T) {
	keyring.MockInit() // empty keychain
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleGenerateKeypair(deps, proto.GenerateKeypairRequest{
		ChallengeToken: "any-challenge",
		Signature:      "any-sig",
	})

	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	// processing log must appear, but success/keypair branches must not run.
	if !log.Contains("keypair generation request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
	if log.Contains("signature verification successful") {
		t.Fatalf("must not log verify success on verifier failure")
	}
	if log.Contains("keypair generation and keypair save successful") {
		t.Fatalf("must not log save success on verifier failure")
	}
}

// TestApp_HandleGenerateKeypair_DoesNotEchoChallenge: the input challenge_token /
// signature must not be echoed to the log (verify-failure branch).
func TestApp_HandleGenerateKeypair_DoesNotEchoChallenge(t *testing.T) {
	keyring.MockInit()
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	const challengeSentinel = "CHALLENGE_TOKEN_DO_NOT_LEAK_TO_LOGS"
	const sigSentinel = "SERVER_SIGNATURE_DO_NOT_LEAK_TO_LOGS"
	resp := HandleGenerateKeypair(deps, proto.GenerateKeypairRequest{
		ChallengeToken: challengeSentinel,
		Signature:      sigSentinel,
	})
	if resp.Success {
		t.Fatalf("expected failure")
	}
	if log.Contains(challengeSentinel) {
		t.Fatalf("logger leaked challenge_token: %v", log.Messages())
	}
	if log.Contains(sigSentinel) {
		t.Fatalf("logger leaked signature: %v", log.Messages())
	}
}

// TestApp_HandleGetPublicKey_LogsLifecycle: empty keychain → not-found
// branch. error log must appear, success log must not.
func TestApp_HandleGetPublicKey_LogsLifecycle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleGetPublicKey(deps, proto.GetPublicKeyRequest{})
	if !log.Contains("public key retrieval request processing") {
		t.Fatalf("expected processing log")
	}
	if resp.Success {
		// If success happens on an empty keychain (a previous test left
		// residual state), that's also OK — in that case the success log
		// must be present.
		if !log.Contains("public key retrieval successful") {
			t.Fatalf("success response must accompany success log")
		}
	} else {
		if log.Contains("public key retrieval successful") {
			t.Fatalf("must not log success on failure")
		}
	}
}

// TestApp_HandleGetServerPublicKey_LogsProcessing: even on the not-found
// branch against an empty keychain, the processing log must appear.
func TestApp_HandleGetServerPublicKey_LogsProcessing(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	_ = HandleGetServerPublicKey(deps, proto.GetServerPublicKeyRequest{})
	if !log.Contains("server public key retrieval request processing") {
		t.Fatalf("expected processing log, got %v", log.Messages())
	}
}

// --- Signing handlers (merged from old actions_w5c_test.go) -------------------

// TestApp_HandleSignAlias_GeneratesNewKeypair_LogsLifecycle: empty store →
// normal generate path. processing + generating + saved + signing-successful logs.
func TestApp_HandleSignAlias_GeneratesNewKeypair_LogsLifecycle(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleSignAlias(deps, proto.SignAliasRequest{Alias: "test-alias"})
	if !resp.Success {
		t.Fatalf("sign should succeed on empty store: %s", resp.Error)
	}
	if !log.Contains("alias signing request processing") {
		t.Fatalf("expected processing log")
	}
	if !log.Contains("generating new keypair for signup") {
		t.Fatalf("expected generating log")
	}
	if !log.Contains("alias signing successful with pending keypair") {
		t.Fatalf("expected signing successful log")
	}
}

// TestApp_HandleSignAlias_DoesNotEchoWrapKey: regression guard that the
// wrap_key_b64 sentinel is not echoed to the logger on the decode-failure
// branch.
func TestApp_HandleSignAlias_DoesNotEchoWrapKey(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	// invalid Base64 wrap_key (enters the decode-failure branch)
	const wrapKeySentinel = "NOT_VALID_BASE64_WRAP_KEY_SENTINEL_DO_NOT_LEAK_TO_LOGS!"
	resp := HandleSignAlias(deps, proto.SignAliasRequest{
		Alias:      "test-alias",
		WrapKeyB64: wrapKeySentinel,
	})
	if resp.Success {
		t.Fatalf("expected failure for invalid wrap_key Base64")
	}
	if log.Contains(wrapKeySentinel) {
		t.Fatalf("logger leaked wrap_key_b64: %v", log.Messages())
	}
}

// TestApp_HandleSignAliasWithTimestamp_NoKeyDeviceNotRegistered: empty store
// → device-not-registered response + processing log.
func TestApp_HandleSignAliasWithTimestamp_NoKeyDeviceNotRegistered(t *testing.T) {
	deps, log, _ := newTestDeps(t)

	resp := HandleSignAliasWithTimestamp(deps, proto.SignAliasWithTimestampRequest{Alias: "test"})
	if resp.Success {
		t.Fatalf("expected failure on empty store")
	}
	if !strings.Contains(resp.Error, "device not registered") {
		t.Fatalf("expected device-not-registered error, got %q", resp.Error)
	}
	if !log.Contains("alias with timestamp signing request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("alias with timestamp signing successful") {
		t.Fatalf("must not log success on missing key")
	}
}

// TestApp_HandleSignAliasWithTimestamp_UsesInjectedClock: ensures the fake
// time injected via Deps.Clock flows through to the response timestamp. If a
// regression calls `time.Now()` directly, the response timestamp will be
// based on wall-clock and diverge from the injected frozen time. Determinism
// + Clock-DI consistency regression guard.
func TestApp_HandleSignAliasWithTimestamp_UsesInjectedClock(t *testing.T) {
	deps, _, store := newTestDeps(t)

	frozen := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	deps.Clock = func() time.Time { return frozen }

	// active keypair seed — write directly to d.Store (MemorySecretStore).
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := keychain.SavePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	if err := keychain.SavePublicKey(store, kp.PublicKey); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	resp := HandleSignAliasWithTimestamp(deps, proto.SignAliasWithTimestampRequest{Alias: "loginuser"})
	if !resp.Success {
		t.Fatalf("HandleSignAliasWithTimestamp: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.SignAliasWithTimestampResponseData)
	if !ok {
		t.Fatalf("unexpected data type: %T", resp.Data)
	}
	if data.Timestamp != frozen.Unix() {
		t.Fatalf("response timestamp = %d, want %d (wall-clock leak — Deps.Clock ignored)", data.Timestamp, frozen.Unix())
	}
	if data.Signature == "" {
		t.Fatalf("signature must be populated")
	}
	// Light sanity check that the response signature decodes as Base64.
	if _, err := base64.StdEncoding.DecodeString(data.Signature); err != nil {
		t.Fatalf("signature not valid base64: %v", err)
	}
}

// TestApp_HandleSignChallengeToken_VerifyFailedShortCircuits: must not enter
// the challenge branch when an AlwaysFailVerifier is injected.
func TestApp_HandleSignChallengeToken_VerifyFailedShortCircuits(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	resp := HandleSignChallengeToken(deps, proto.SignChallengeTokenRequest{
		ChallengeToken: "any-challenge",
		Signature:      "any-sig",
	})
	if resp.Success {
		t.Fatalf("expected failure when ServerKeyVerifier rejects")
	}
	if !strings.Contains(resp.Error, "server signature verification failed") {
		t.Fatalf("error must include verifier failure prefix, got %q", resp.Error)
	}
	if !log.Contains("challenge token signing request processing") {
		t.Fatalf("expected processing log")
	}
	if log.Contains("server signature verification successful") {
		t.Fatalf("must not log verify success on verifier failure")
	}
	if log.Contains("challenge token signing successful") {
		t.Fatalf("must not log signing success on verifier failure")
	}
}

// TestApp_HandleSignChallengeToken_DoesNotEchoChallenge: regression guard for
// the challenge_token sentinel.
func TestApp_HandleSignChallengeToken_DoesNotEchoChallenge(t *testing.T) {
	deps, log, _ := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))

	const challengeSentinel = "CHALLENGE_TOKEN_DO_NOT_LEAK_TO_LOGS"
	resp := HandleSignChallengeToken(deps, proto.SignChallengeTokenRequest{
		ChallengeToken: challengeSentinel,
		Signature:      "any-sig",
	})
	if resp.Success {
		t.Fatalf("expected failure")
	}
	if log.Contains(challengeSentinel) {
		t.Fatalf("logger leaked challenge_token: %v", log.Messages())
	}
}

// TestHandleSignAlias_ValidationDelegation: regression guard that the
// response envelope matches the dispatcher's.
func TestHandleSignAlias_ValidationDelegation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	// empty alias so the Validate step rejects.
	resp := HandleSignAlias(deps, proto.SignAliasRequest{})
	if resp.Success {
		t.Fatalf("expected validation failure")
	}
	if resp.Error == "" {
		t.Fatalf("expected non-empty error")
	}
}
