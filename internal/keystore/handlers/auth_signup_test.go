package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

func TestHandleAuthSignupPrepareDoesNotReturnSecrets(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x44}, 32))
	password := "correct horse battery staple"
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x01}, 128))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{
		Alias: "alice", Password: password, RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ",
	})
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
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{password, "recovery_key\"", "wrap_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("response contains forbidden secret field/value %q", forbidden)
		}
	}
}

func TestHandleAuthSignupPrepareUsesAppPassword(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x55}, 32))
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x02}, 128))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{
		Alias: "alice", Password: "correct horse battery staple",
		RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ",
	})
	if !response.Success {
		t.Fatalf("HandleAuthSignupPrepare: %s", response.Error)
	}
}

func TestHandleAuthSignupPrepareRejectsShortPassword(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x22}, 32))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice", Password: "short", RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"})
	if response.Success || response.ErrorCode != "validation_error" {
		t.Fatalf("response = %+v", response)
	}
	if deps.RecoveryKeySessions.Size() != 0 {
		t.Fatal("short password must not leave a recovery key handle")
	}
}

func TestHandleAuthSignupPrepareCountsUnicodeCharacters(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setKeychainDeviceKey(t, store, bytes.Repeat([]byte{0x22}, 32))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice", Password: "가나다라", RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"})
	if response.Success || response.ErrorCode != "validation_error" {
		t.Fatalf("response = %+v", response)
	}
	if deps.RecoveryKeySessions.Size() != 0 {
		t.Fatal("short Unicode password must not leave a recovery key handle")
	}
}

func TestHandleAuthSignupPrepareCreatesDeviceKeyInsideKeeper(t *testing.T) {
	deps, _, store := newTestDeps(t)
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x03}, 256))

	response := HandleAuthSignupPrepare(deps, proto.AuthSignupPrepareRequest{Alias: "alice", Password: "correct horse battery staple", RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"})
	if !response.Success {
		t.Fatalf("HandleAuthSignupPrepare: %s", response.Error)
	}
	stored, err := keychain.GetDeviceKey(store)
	if err != nil {
		t.Fatalf("GetDeviceKey: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil || len(raw) != 32 {
		t.Fatalf("stored device key is invalid")
	}
}

func TestHandleAuthRecoveryReissuePrepareKeepsRKOutOfResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)
	const activePEM = "-----BEGIN PRIVATE KEY-----\nACTIVE-KEY\n-----END PRIVATE KEY-----"
	if err := keychain.SavePrivateKey(store, activePEM); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	deps.Rand = bytes.NewReader(bytes.Repeat([]byte{0x05}, 128))

	response := HandleAuthRecoveryReissuePrepare(deps, proto.AuthRecoveryReissuePrepareRequest{
		Alias: "alice", RecoveryKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ",
	})
	if !response.Success {
		t.Fatalf("HandleAuthRecoveryReissuePrepare: %s", response.Error)
	}
	data := response.Data.(proto.AuthRecoveryReissuePrepareResponseData)
	if data.RecoveryAuthSeed == "" || data.RecoveryWrappedKeeper == "" {
		t.Fatalf("reissue material missing: %+v", data)
	}

	_, wrapKey, err := recoverykey.Derive([]byte("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"), "alice", data.RecoveryKeyVersion)
	if err != nil {
		t.Fatalf("derive recovery key: %v", err)
	}
	decrypted, err := keepercrypto.AESGCMDecryptBase64(wrapKey, data.RecoveryWrappedKeeper)
	secure.Zeroize(wrapKey)
	if err != nil {
		t.Fatalf("decrypt wrapped keeper: %v", err)
	}
	if string(decrypted) != activePEM {
		t.Fatal("wrapped keeper does not contain the active private key")
	}
	secure.Zeroize(decrypted)

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{"recovery_key\"", "wrap_key", activePEM} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("reissue response contains forbidden secret field/value %q", forbidden)
		}
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

	beginResponse := HandleAuthRecoveryBegin(deps, proto.AuthRecoveryBeginRequest{
		Alias:       "alice",
		RecoveryKey: enteredRecoveryKey,
	})
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
		NewRecoveryKey:     "ZYXW-VUTS-RQPN-MLKJ-HGFE-DCBA",
	})
	if !prepareResponse.Success {
		t.Fatalf("HandleAuthRecoveryPrepare: %s", prepareResponse.Error)
	}
	data := prepareResponse.Data.(proto.AuthRecoveryPrepareResponseData)
	t.Cleanup(func() {
		deps.RecoverySessions.Close(data.RecoveryHandle)
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
