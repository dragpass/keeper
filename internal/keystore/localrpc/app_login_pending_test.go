package localrpc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// exactServerVerifier accepts a server signature only for the token it was
// made over, so a binding for one key or challenge does not pass for another.
type exactServerVerifier struct{}

func serverSig(token string) string { return "server-sig:" + token }

func (exactServerVerifier) Verify(token, sig string, _ uint) error {
	if sig != serverSig(token) {
		return errors.New("server signature verification failed")
	}
	return nil
}

func verifySigned(t *testing.T, publicKeyPEM, data, signature string) bool {
	t.Helper()
	key, err := keepercrypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	return keepercrypto.VerifySignature(key, data, raw) == nil
}

// A signup the server accepted whose page was lost before save_session_code:
// the normal sign-in has no key, the pending routes sign with the staged key
// only for the server-named fingerprint and a correct password, and only the
// server's session code promotes it.
func TestAppPendingLoginRoutesSignWithTheStagedKeyThenPromote(t *testing.T) {
	server := newTestServer(t)
	server.app.ServerKeyVerifier = exactServerVerifier{}
	store := server.app.Store.(*keychain.MemorySecretStore)
	session, csrf := openTestSession(t, server)

	const alias, password = "alice", "correct horse battery staple"
	code, prepared, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", map[string]string{
		"alias": alias, "password": password, "recovery_key": "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ",
	})
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("signup prepare: %d %s", code, body)
	}
	var signup proto.AuthSignupPrepareResponseData
	_ = json.Unmarshal(prepared.Data, &signup)
	staged := keepercrypto.AccountKeyFingerprint([]byte(signup.PublicKey))
	lost := store.Snapshot()

	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/login/sign-alias",
		map[string]string{"alias": alias}); code != http.StatusOK || result.Success || result.ErrorCode != "not_found" {
		t.Fatalf("normal sign-in without an active key: %d %s", code, body)
	}

	code, signed, body := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-alias",
		map[string]string{"alias": alias})
	if code != http.StatusOK || !signed.Success {
		t.Fatalf("pending sign alias: %d %s", code, body)
	}
	var aliasData proto.AuthLoginPendingSignAliasResponseData
	_ = json.Unmarshal(signed.Data, &aliasData)
	if len(aliasData.Candidates) != 1 || aliasData.Candidates[0].PublicKeyFingerprint != staged {
		t.Fatalf("candidates = %+v", aliasData.Candidates)
	}

	challenge := func(fingerprint, pw string) map[string]any {
		return map[string]any{
			"challenge_token": "challenge", "signature": serverSig("challenge"), "server_key_version": 1,
			"account_key_fingerprint":        fingerprint,
			"account_key_signature":          serverSig(proto.LoginAccountKeyBinding("challenge", fingerprint)),
			"account_key_server_key_version": 1,
			"password":                       pw, "encrypted_dek_b64": signup.PasswordWrappedDEKB64,
		}
	}
	other := keepercrypto.AccountKeyFingerprint([]byte(routeKeypair(t).PublicKey))
	for name, request := range map[string]map[string]any{
		"wrong password":          challenge(staged, "not the password at all"),
		"server key matches none": challenge(other, password),
		"App-asserted binding":    func() map[string]any { r := challenge(staged, password); r["account_key_signature"] = "x"; return r }(),
	} {
		code, result, body := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-challenge", request)
		if code != http.StatusOK || result.Success || strings.Contains(body, password) {
			t.Fatalf("%s: %d %s", name, code, body)
		}
		if !reflect.DeepEqual(store.Snapshot(), lost) {
			t.Fatalf("%s changed the keyring", name)
		}
	}
	withStage := challenge(staged, password)
	withStage["stage"] = "recovery"
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-challenge", withStage); code != http.StatusBadRequest {
		t.Fatalf("a caller-chosen stage was accepted: %d", code)
	}

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-challenge", challenge(staged, password))
	if code != http.StatusOK || !result.Success {
		t.Fatalf("pending sign challenge: %d %s", code, body)
	}
	var challengeData proto.SignChallengeTokenResponseData
	_ = json.Unmarshal(result.Data, &challengeData)
	if !verifySigned(t, signup.PublicKey, "challenge", challengeData.Signature) {
		t.Fatal("the challenge was not signed with the staged key")
	}
	if !reflect.DeepEqual(store.Snapshot(), lost) {
		t.Fatal("pending signing changed the keyring")
	}

	encrypted := wrapTo(t, signup.PublicKey, []byte("reissued-session"))
	save := map[string]any{"encrypted_session_code": encrypted, "signature": serverSig(encrypted), "server_key_version": 1}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/signup/save-session-code", save); code != http.StatusOK || !result.Success || strings.Contains(body, "reissued-session") {
		t.Fatalf("save session code: %d %s", code, body)
	}
	if active, _ := keychain.GetPublicKey(store); active != signup.PublicKey {
		t.Fatal("the staged key was not promoted")
	}
	promoted := store.Snapshot()
	if code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/signup/save-session-code", save); code != http.StatusOK || !result.Success {
		t.Fatal("a repeated save failed")
	}
	if !reflect.DeepEqual(store.Snapshot(), promoted) {
		t.Fatal("a repeated save changed the keyring")
	}
	if code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-alias",
		map[string]string{"alias": alias}); code != http.StatusOK || result.Success || result.ErrorCode != "not_found" {
		t.Fatal("the pending sign-in still answers after promotion")
	}
	if code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/login/sign-alias",
		map[string]string{"alias": alias}); code != http.StatusOK || !result.Success {
		t.Fatal("the normal sign-in does not work after promotion")
	}
}
