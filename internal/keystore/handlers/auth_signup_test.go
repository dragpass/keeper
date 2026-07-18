package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/awnumar/memguard"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

type signupUserPresence struct {
	userpresence.Unavailable
	password   string
	shownKey   string
	showErr    error
	newPrompts int
}

func (p *signupUserPresence) Capabilities() userpresence.Capabilities {
	return userpresence.Capabilities{
		Available:       true,
		PromptSecret:    true,
		PromptNewSecret: true,
		ShowRecoveryKey: true,
		Backend:         "test",
	}
}

func (p *signupUserPresence) PromptSecret(context.Context, userpresence.SecretPrompt) (userpresence.SecretResult, error) {
	return userpresence.SecretResult{Secret: memguard.NewBufferFromBytes([]byte(p.password))}, nil
}

func (p *signupUserPresence) PromptNewSecret(context.Context, userpresence.NewSecretPrompt) (userpresence.SecretResult, error) {
	p.newPrompts++
	return userpresence.SecretResult{Secret: memguard.NewBufferFromBytes([]byte(p.password))}, nil
}

func (p *signupUserPresence) ShowRecoveryKey(_ context.Context, prompt userpresence.RecoveryKeyPrompt) error {
	p.shownKey = string(prompt.RecoveryKey.Bytes())
	return p.showErr
}

func TestHandleAuthSignupPrepareDoesNotReturnSecrets(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
	password := "correct horse battery staple"
	presence := &signupUserPresence{password: password}
	deps.UserPresence = presence
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x01}, 128))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice"})
	if !response.Success {
		t.Fatalf("HandleAuthSignupPrepare: %s", response.Error)
	}
	data := response.Data.(proto.AuthSignupPrepareResponseData)
	if data.PasswordWrappedDEKB64 == "" || data.DeviceWrappedDEKB64 == "" || data.RecoveryAuthSeed == "" {
		t.Fatalf("encrypted signup material missing: %+v", data)
	}
	if data.PublicKey == "" || data.Signature == "" || data.RecoveryWrappedKeeper == "" {
		t.Fatalf("identity material missing: %+v", data)
	}
	if exists, _ := deps.RecoveryKeySessions.Status(data.RecoveryKeyHandle); !exists {
		t.Fatal("recovery key handle must remain live until native display")
	}
	t.Cleanup(func() { deps.RecoveryKeySessions.Close(data.RecoveryKeyHandle) })

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{password, "recovery_key\"", "wrap_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("response contains forbidden secret field/value %q", forbidden)
		}
	}
	if presence.newPrompts != 1 {
		t.Fatalf("new password prompts = %d, want 1", presence.newPrompts)
	}
}

func TestHandleAuthSignupPrepareRejectsShortPassword(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x22}, 32))
	deps.UserPresence = &signupUserPresence{password: "short"}

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice"})
	if response.Success || response.ErrorCode != "validation_error" {
		t.Fatalf("response = %+v", response)
	}
	if deps.RecoveryKeySessions.Size() != 0 {
		t.Fatal("short password must not leave a recovery key handle")
	}
}

func TestHandleAuthSignupPrepareCreatesDeviceKeyInsideKeeper(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deps.UserPresence = &signupUserPresence{password: "correct horse battery staple"}
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x03}, 256))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice"})
	if !response.Success {
		t.Fatalf("HandleAuthSignupPrepare: %s", response.Error)
	}
	data := response.Data.(proto.AuthSignupPrepareResponseData)
	t.Cleanup(func() { deps.RecoveryKeySessions.Close(data.RecoveryKeyHandle) })
	stored, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil || len(raw) != 32 {
		t.Fatalf("stored device key is invalid")
	}
}

func TestHandleAuthRecoveryKeyShowConsumesHandleOnSuccess(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	presence := &signupUserPresence{}
	deps.UserPresence = presence
	handle, _, err := deps.RecoveryKeySessions.Open([]byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	response := HandleAuthRecoveryKeyShow(deps, proto.AuthRecoveryKeyShowRequest{RecoveryKeyHandle: handle})
	if !response.Success {
		t.Fatalf("HandleAuthRecoveryKeyShow: %s", response.Error)
	}
	if presence.shownKey != "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ" {
		t.Fatalf("shown key = %q", presence.shownKey)
	}
	if exists, _ := deps.RecoveryKeySessions.Status(handle); exists {
		t.Fatal("successful display must consume the handle")
	}
}

func TestHandleAuthRecoveryKeyShowKeepsHandleAfterCancel(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.UserPresence = &signupUserPresence{showErr: userpresence.ErrDenied}
	handle, _, err := deps.RecoveryKeySessions.Open([]byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { deps.RecoveryKeySessions.Close(handle) })

	response := HandleAuthRecoveryKeyShow(deps, proto.AuthRecoveryKeyShowRequest{RecoveryKeyHandle: handle})
	if response.Success {
		t.Fatalf("cancel response = %+v", response)
	}
	if err := deps.RecoveryKeySessions.Use(handle, func([]byte) error { return nil }); err != nil {
		t.Fatalf("cancel must keep handle: %v", err)
	}
}

func TestRecoveryKeySessionErrorsMapToSessionCodes(t *testing.T) {
	if response := sessionUseError(sessions.ErrRecoveryKeySessionNotFound, "test"); response.ErrorCode != "not_found" {
		t.Fatalf("not found response = %+v", response)
	}
}

func TestHandleAuthRecoveryBeginAndPrepareKeepRKOutOfResponse(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	enteredRecoveryKey := "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	deps.UserPresence = &signupUserPresence{password: enteredRecoveryKey}
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x02}, 256))

	oldKeypair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	_, oldWrapKey, err := recoverykey.Derive([]byte(enteredRecoveryKey), "alice", recoverykey.Version)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	wrappedOldKey, err := keepercrypto.AESGCMEncryptBase64(oldWrapKey, []byte(oldKeypair.PrivateKey))
	secure.Zeroize(oldWrapKey)
	if err != nil {
		t.Fatalf("AESGCMEncryptBase64: %v", err)
	}

	beginResponse := HandleAuthRecoveryBegin(deps, proto.AuthRecoveryBeginRequest{Alias: "alice"})
	if !beginResponse.Success {
		t.Fatalf("HandleAuthRecoveryBegin: %s", beginResponse.Error)
	}
	beginData := beginResponse.Data.(proto.AuthRecoveryBeginResponseData)

	prepareResponse := HandleAuthRecoveryPrepare(deps, proto.AuthRecoveryPrepareRequest{
		Alias:              "alice",
		EnteredKeyHandle:   beginData.EnteredKeyHandle,
		ChallengeToken:     "server-challenge",
		Signature:          "server-signature",
		WrappedKeeperB64:   wrappedOldKey,
		RecoveryKeyVersion: recoverykey.Version,
		ServerKeyVersion:   1,
	})
	if !prepareResponse.Success {
		t.Fatalf("HandleAuthRecoveryPrepare: %s", prepareResponse.Error)
	}
	data := prepareResponse.Data.(proto.AuthRecoveryPrepareResponseData)
	t.Cleanup(func() {
		deps.RecoverySessions.Close(data.RecoveryHandle)
		deps.RecoveryKeySessions.Close(data.NewRecoveryKeyHandle)
	})
	if data.OldChallengeSignature == "" || data.NewPublicKey == "" || data.NewWrappedKeeper == "" {
		t.Fatalf("recovery output missing: %+v", data)
	}
	if exists, _ := deps.RecoveryKeySessions.Status(beginData.EnteredKeyHandle); exists {
		t.Fatal("prepare must consume the entered recovery key handle")
	}
	if exists, _ := deps.RecoverySessions.Status(data.RecoveryHandle); !exists {
		t.Fatal("old private key handle must remain for group DEK rewrap")
	}
	if exists, _ := deps.RecoveryKeySessions.Status(data.NewRecoveryKeyHandle); !exists {
		t.Fatal("new recovery key handle must remain for native display")
	}

	encoded, err := json.Marshal(prepareResponse)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{enteredRecoveryKey, "wrap_key", "recovery_key\""} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("prepare response contains forbidden secret field/value %q", forbidden)
		}
	}
}
