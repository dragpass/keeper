//go:build mls && cgo

// pending_login_process_mls_test.go — the sign-in with a staged account key
// (a recovery the server accepted whose page was lost before
// save_session_code), on the Keeper binary, killed between the steps and in
// the middle of the promotion. Nothing before save_session_code writes, and
// the promotion starts only once the server's session code opened with the
// staged key, so no kill leaves a key active that the server did not accept.

package killharness

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const pendingPassword = "correct horse battery staple"

func (d *device) keyringPath() string { return filepath.Join(d.dir, "keyring.json") }

func (d *device) keyringBytes() []byte {
	d.t.Helper()
	raw, err := os.ReadFile(d.keyringPath())
	if err != nil {
		d.t.Fatal(err)
	}
	return raw
}

func (d *device) keyringEntries() map[string]string {
	d.t.Helper()
	var entries map[string]string
	if err := json.Unmarshal(d.keyringBytes(), &entries); err != nil {
		d.t.Fatal(err)
	}
	return entries
}

// stage adds a staged recovery keypair to the keyring file, as a prepare the
// server then accepted would have left it.
func (d *device) stage(pair *crypto.KeyPair) {
	d.t.Helper()
	entries := d.keyringEntries()
	entries[config.Service+"|"+config.PendingRecoveryKeeperPrivateKey] = pair.PrivateKey
	entries[config.Service+"|"+config.PendingRecoveryKeeperPublicKey] = pair.PublicKey
	entries[config.Service+"|"+config.SessionCode] = "session-code-of-the-old-key"
	raw, err := json.Marshal(entries)
	if err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(d.keyringPath(), raw, 0o600); err != nil {
		d.t.Fatal(err)
	}
}

// passwordWrappedDEK is the server's accounts.encrypted_dek for password:
// salt(16) || iv(12) || AES-GCM(PBKDF2(password), DEK).
func passwordWrappedDEK(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, handlers.DekSaltLength)
	dek := make([]byte, 32)
	iv := make([]byte, 12)
	for _, b := range [][]byte{salt, dek, iv} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	kek := pbkdf2.Key([]byte(password), salt, handlers.DekPBKDF2Iterations, handlers.DekKEKLength, sha256.New)
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	out := append(append(salt, iv...), gcm.Seal(nil, iv, dek, nil)...)
	return base64.StdEncoding.EncodeToString(out)
}

func encryptTo(t *testing.T, publicKeyPEM, code string) string {
	t.Helper()
	key, err := crypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptData(key, []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

func pendingChallenge(t *testing.T, fingerprint, password, encryptedDEK string) proto.AuthLoginPendingSignChallengeRequest {
	const challenge = "server-login-challenge"
	return proto.AuthLoginPendingSignChallengeRequest{
		ChallengeToken: challenge, Signature: sign(t, challenge), ServerKeyVersion: 1,
		AccountKeyFingerprint:      fingerprint,
		AccountKeySignature:        sign(t, proto.LoginAccountKeyBinding(challenge, fingerprint)),
		AccountKeyServerKeyVersion: 1,
		Password:                   password, EncryptedDEKB64: encryptedDEK,
	}
}

func saveRequest(t *testing.T, publicKeyPEM, code string) proto.SaveSessionCodeRequest {
	encrypted := encryptTo(t, publicKeyPEM, code)
	return proto.SaveSessionCodeRequest{EncryptedSessionCode: encrypted, Signature: sign(t, encrypted), ServerKeyVersion: 1}
}

func TestKeeperKilledDuringAPendingSignInNeverPromotesAKeyTheServerDidNotAccept(t *testing.T) {
	d := newDevice(t, hAlice)
	staged, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	d.stage(staged)
	oldPublic := d.keyringEntries()[config.Service+"|"+config.DragPassKeeperPublicKey]
	stagedFP := crypto.AccountKeyFingerprint([]byte(staged.PublicKey))
	encryptedDEK := passwordWrappedDEK(t, pendingPassword)
	lost := d.keyringBytes()

	p := d.start("", 0)
	var aliasData proto.AuthLoginPendingSignAliasResponseData
	p.must(proto.ActionAuthLoginPendingSignAlias, proto.AuthLoginPendingSignAliasRequest{Alias: "alice"}, &aliasData)
	if len(aliasData.Candidates) != 1 || aliasData.Candidates[0].PublicKeyFingerprint != stagedFP {
		t.Fatalf("candidates = %+v", aliasData.Candidates)
	}
	p.refused(proto.ActionAuthLoginPendingSignChallenge,
		pendingChallenge(t, stagedFP, "not the password at all", encryptedDEK), "password_invalid")
	p.refused(proto.ActionAuthLoginPendingSignChallenge,
		pendingChallenge(t, crypto.AccountKeyFingerprint([]byte(other.PublicKey)), pendingPassword, encryptedDEK), "not_found")
	var signed proto.SignChallengeTokenResponseData
	p.must(proto.ActionAuthLoginPendingSignChallenge, pendingChallenge(t, stagedFP, pendingPassword, encryptedDEK), &signed)
	if !bytes.Equal(d.keyringBytes(), lost) {
		t.Fatal("the pending sign-in wrote to the keyring")
	}

	// Killed between the sign-in and save_session_code: nothing to finish.
	p.killAndAssertKilled()
	if !bytes.Equal(d.keyringBytes(), lost) {
		t.Fatal("a kill after the pending sign-in changed the keyring")
	}

	// A session code the server encrypted to some other key promotes nothing.
	p = d.start("", 0)
	p.refused(proto.ActionSaveSessionCode, saveRequest(t, other.PublicKey, "someone-elses-code"), "crypto_failure")
	if !bytes.Equal(d.keyringBytes(), lost) {
		t.Fatal("a session code for another key changed the keyring")
	}
	p.kill()

	// Killed in the middle of the promotion of the key the server accepted:
	// the staged slots are still there, and the retry finishes it.
	p = d.start(keychain.CrashSessionCodeAfterPrivateKey, 0)
	accepted := saveRequest(t, staged.PublicKey, "reissued-session-code")
	p.parkAt(proto.ActionSaveSessionCode, accepted)
	p.killAndAssertKilled()
	mid := d.keyringEntries()
	if mid[config.Service+"|"+config.PendingRecoveryKeeperPublicKey] != staged.PublicKey {
		t.Fatal("the staged key was dropped before its promotion finished")
	}
	if mid[config.Service+"|"+config.DragPassKeeperPublicKey] != oldPublic {
		t.Fatal("the crash point is not where the promotion is half done")
	}

	p = d.start("", 0)
	p.must(proto.ActionSaveSessionCode, accepted, nil)
	done := d.keyringEntries()
	if done[config.Service+"|"+config.DragPassKeeperPrivateKey] != staged.PrivateKey ||
		done[config.Service+"|"+config.DragPassKeeperPublicKey] != staged.PublicKey ||
		done[config.Service+"|"+config.SessionCode] != "reissued-session-code" {
		t.Fatal("the retried save did not finish the promotion")
	}
	if _, left := done[config.Service+"|"+config.PendingRecoveryKeeperPublicKey]; left {
		t.Fatal("the staged slots outlived the promotion")
	}
	promoted := d.keyringBytes()
	p.must(proto.ActionSaveSessionCode, accepted, nil)
	if !bytes.Equal(d.keyringBytes(), promoted) {
		t.Fatal("a repeated save changed the keyring")
	}
	p.refused(proto.ActionAuthLoginPendingSignAlias, proto.AuthLoginPendingSignAliasRequest{Alias: "alice"}, "not_found")
}
