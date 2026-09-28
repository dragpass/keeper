package localrpc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore"
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
	code, result, body = callRoute(t, server, session, csrf, "/v1/auth/signup/save-session-code", save)
	if code != http.StatusOK || !result.Success || strings.Contains(body, "reissued-session") {
		t.Fatalf("save session code: %d %s", code, body)
	}
	// The App learns which stage became active, never the session code.
	var saved map[string]any
	_ = json.Unmarshal(result.Data, &saved)
	if !reflect.DeepEqual(saved, map[string]any{"stored": true, "promoted": "signup"}) {
		t.Fatalf("save session code answered %s", result.Data)
	}
	if active, _ := keychain.GetPublicKey(store); active != signup.PublicKey {
		t.Fatal("the staged key was not promoted")
	}
	promoted := store.Snapshot()
	if code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/signup/save-session-code", save); code != http.StatusOK || !result.Success || !strings.Contains(string(result.Data), `"promoted":"active"`) {
		t.Fatal("a repeated save failed or did not report the already active key")
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

// Q8 over the App route: while a signup is staged another input is refused
// and the keyring keeps its bytes; the abort route drops it by public key.
func TestAppSignupRoutesRefuseAnotherInputWhileStagedAndAbort(t *testing.T) {
	server := newTestServer(t)
	store := server.app.Store.(*keychain.MemorySecretStore)
	session, csrf := openTestSession(t, server)
	input := map[string]string{"alias": "alice", "password": "correct horse battery staple", "recovery_key": "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"}
	code, prepared, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", input)
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("signup prepare: %d %s", code, body)
	}
	var signup proto.AuthSignupPrepareResponseData
	_ = json.Unmarshal(prepared.Data, &signup)
	staged := store.Snapshot()

	other := map[string]string{"alias": "alice", "password": "correct horse battery staple", "recovery_key": "ZZZZ-EFGH-JKLM-NPQR-STUV-WXYZ"}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", other); code != http.StatusOK || result.Success || result.ErrorCode != "signup_pending" {
		t.Fatalf("another input while staged: %d %s", code, body)
	}
	if !reflect.DeepEqual(store.Snapshot(), staged) {
		t.Fatal("a refused prepare changed the keyring")
	}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/recovery-key/reissue-prepare",
		map[string]string{"alias": "alice", "recovery_key": "ZZZZ-EFGH-JKLM-NPQR-STUV-WXYZ"}); code != http.StatusOK || result.ErrorCode != "account_key_staged" {
		t.Fatalf("reissue while staged: %d %s", code, body)
	}
	code, aborted, body := callRoute(t, server, session, csrf, "/v1/auth/signup/abort", map[string]string{"publickey": signup.PublicKey})
	if code != http.StatusOK || !aborted.Success || !strings.Contains(string(aborted.Data), `"discarded":true`) {
		t.Fatalf("abort: %d %s", code, body)
	}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", other); code != http.StatusOK || !result.Success {
		t.Fatalf("a new signup after the abort: %d %s", code, body)
	}
}

// The pending sign-in and the signup retry are account entry, not chat: they
// run while another App session holds the chat runtime lease, with no epoch,
// and the same-input retry still answers for the staged key.
func TestAppPendingLoginRoutesRunBesideAHeldChatRuntimeLease(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*keychain.MemorySecretStore)
	chatSession, chatCSRF := openTestSession(t, server)
	if granted := claimLease(t, server, chatSession, chatCSRF, routeHolder); !granted.Success {
		t.Fatalf("claim: %+v", granted)
	}
	session, csrf := openTestSession(t, server)

	const alias = "alice"
	input := map[string]string{"alias": alias, "password": "correct horse battery staple", "recovery_key": "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"}
	code, prepared, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", input)
	if code != http.StatusOK || !prepared.Success {
		t.Fatalf("signup prepare beside the lease: %d %s", code, body)
	}
	var first proto.AuthSignupPrepareResponseData
	_ = json.Unmarshal(prepared.Data, &first)
	staged := store.Snapshot()

	code, retried, body := callRoute(t, server, session, csrf, "/v1/auth/signup/prepare", input)
	if code != http.StatusOK || !retried.Success {
		t.Fatalf("same-input retry beside the lease: %d %s", code, body)
	}
	var again proto.AuthSignupPrepareResponseData
	_ = json.Unmarshal(retried.Data, &again)
	if again.PublicKey != first.PublicKey || !reflect.DeepEqual(store.Snapshot(), staged) {
		t.Fatal("the retry did not answer for the staged key without writing")
	}

	code, signed, body := callRoute(t, server, session, csrf, "/v1/auth/login/pending/sign-alias", map[string]string{"alias": alias})
	if code != http.StatusOK || !signed.Success {
		t.Fatalf("pending sign alias beside the lease: %d %s", code, body)
	}

	if _, result := callWithEpoch(t, server, session, csrf, "/v1/chat/mls_leaf_abort", map[string]any{}, ""); result.ErrorCode != keystore.ErrCodeChatRuntimeLeaseRequired {
		t.Fatalf("the signing-in session reached a gated chat route: %+v", result)
	}
}
