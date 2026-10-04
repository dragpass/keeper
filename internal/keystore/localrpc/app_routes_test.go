package localrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	routeOwner = "11111111-1111-4111-8111-111111111111"
	routePeer  = "22222222-2222-4222-8222-222222222222"
)

type routeResult struct {
	Success   bool            `json:"success"`
	Error     string          `json:"error"`
	ErrorCode string          `json:"error_code"`
	Data      json.RawMessage `json:"data"`
}

func callRoute(t *testing.T, server *Server, session, csrf, path string, body any) (int, routeResult, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response := localRequest(server, http.MethodPost, path, string(raw), session, csrf)
	var result routeResult
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatalf("%s answer: %v", path, err)
		}
	}
	return response.Code, result, response.Body.String()
}

func routeKeypair(t *testing.T) *keepercrypto.KeyPair {
	t.Helper()
	pair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func wrapTo(t *testing.T, publicKeyPEM string, secret []byte) string {
	t.Helper()
	key, err := keepercrypto.ParsePublicKey(publicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := keepercrypto.EncryptData(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

func openWith(t *testing.T, privateKeyPEM, wrappedB64 string) []byte {
	t.Helper()
	key, err := keepercrypto.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := keepercrypto.DecryptData(key, raw)
	if err != nil {
		t.Fatalf("does not open: %v", err)
	}
	return opened
}

// The whole App recovery through the typed routes: nothing active changes
// until the server's session code opens with the staged key, and the group
// DEK rewrap lands on this Keeper's promoted key.
func TestAppRecoveryRoutesStageThenPromote(t *testing.T) {
	server := newTestServer(t)
	server.app.ServerKeyVerifier = testdouble.AlwaysOKVerifier{}
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)

	const alias, rk, newRK = "alice", "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ", "ZYXW-VUTS-RQPN-MLKJ-HGFE-DCBA"
	old := routeKeypair(t)
	_, wrapKey, err := recoverykey.Derive([]byte(rk), alias, recoverykey.Version)
	if err != nil {
		t.Fatal(err)
	}
	wrappedOld, err := keepercrypto.AESGCMEncryptBase64(wrapKey, []byte(old.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()

	code, begin, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/begin",
		map[string]string{"alias": alias, "recovery_key": rk})
	if code != http.StatusOK || !begin.Success || strings.Contains(body, rk) {
		t.Fatalf("begin: %d %s", code, body)
	}
	var beginData proto.AuthRecoveryBeginResponseData
	_ = json.Unmarshal(begin.Data, &beginData)

	code, prepared, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/prepare", map[string]any{
		"alias": alias, "entered_recovery_key_handle": beginData.EnteredKeyHandle,
		"challenge_token": "server-challenge", "signature": "server-signature",
		"wrapped_keeper_b64": wrappedOld, "recovery_key_version": recoverykey.Version,
		"server_key_version": 1, "new_recovery_key": newRK,
		"account_id": routeOwner, "rotated_at": time.Now().Unix(),
	})
	if code != http.StatusOK || !prepared.Success || strings.Contains(body, newRK) || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("prepare: %d %s", code, body)
	}
	var prep proto.AuthRecoveryPrepareResponseData
	_ = json.Unmarshal(prepared.Data, &prep)
	after := store.Snapshot()
	for key, value := range before {
		if after[key] != value {
			t.Fatalf("prepare changed %s before the server accepted", key)
		}
	}

	groupDEK := bytes.Repeat([]byte{0x33}, 32)
	rewrap := map[string]any{
		"challenge_token": "server-challenge", "signature": "server-signature",
		"recovery_handle": prep.RecoveryHandle, "encrypted_group_dek": wrapTo(t, old.PublicKey, groupDEK),
		"server_key_version": 1,
	}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/rewrap-group-dek", rewrap); code != http.StatusOK || result.Success {
		t.Fatalf("rewrap before acceptance: %d %s", code, body)
	}

	if code, result, body := callRoute(t, server, session, csrf, "/v1/auth/signup/save-session-code", map[string]any{
		"encrypted_session_code": wrapTo(t, prep.NewPublicKey, []byte("new-session")),
		"signature":              "server-signature", "server_key_version": 1,
	}); code != http.StatusOK || !result.Success || strings.Contains(body, "new-session") {
		t.Fatalf("save session code: %d %s", code, body)
	}
	if active, _ := keychain.GetPublicKey(store); active != prep.NewPublicKey {
		t.Fatal("the accepted recovery key was not promoted")
	}

	code, result, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/rewrap-group-dek", rewrap)
	if code != http.StatusOK || !result.Success {
		t.Fatalf("rewrap after acceptance: %d %s", code, body)
	}
	var rewrapped proto.DEKRewrapWithOldKeyResponseData
	_ = json.Unmarshal(result.Data, &rewrapped)
	activePrivate, _ := keychain.GetPrivateKey(store)
	if !bytes.Equal(openWith(t, activePrivate, rewrapped.NewEncryptedGroupDEK), groupDEK) {
		t.Fatal("the rewrap is not to the promoted key")
	}

	withTarget := map[string]any{}
	for key, value := range rewrap {
		withTarget[key] = value
	}
	withTarget["new_public_key"] = routeKeypair(t).PublicKey
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/auth/recovery/rewrap-group-dek", withTarget); code != http.StatusBadRequest {
		t.Fatalf("a caller-chosen rewrap target was accepted: %d", code)
	}

	if code, result, _ := callRoute(t, server, session, csrf, "/v1/auth/recovery/close",
		map[string]string{"recovery_handle": prep.RecoveryHandle}); code != http.StatusOK || !result.Success {
		t.Fatalf("close: %d", code)
	}
}

// A refused recovery through the routes, and an abort after the server
// refused, both leave the keyring byte-identical.
func TestAppRecoveryRoutesRefuseAndAbortWithoutAKeyringChange(t *testing.T) {
	server := newTestServer(t)
	server.app.ServerKeyVerifier = testdouble.AlwaysOKVerifier{}
	store := server.app.Store.(*testdouble.MemorySecretStore)
	owner := routeKeypair(t)
	if err := keychain.SavePrivateKey(store, owner.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, owner.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveSessionCode(store, "before"); err != nil {
		t.Fatal(err)
	}
	session, csrf := openTestSession(t, server)
	const alias, rk = "alice", "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
	_, wrapKey, _ := recoverykey.Derive([]byte(rk), alias, recoverykey.Version)
	wrappedOld, _ := keepercrypto.AESGCMEncryptBase64(wrapKey, []byte(owner.PrivateKey))
	before := store.Snapshot()

	prepare := func(entered string) (routeResult, string) {
		_, begin, _ := callRoute(t, server, session, csrf, "/v1/auth/recovery/begin",
			map[string]string{"alias": alias, "recovery_key": entered})
		var beginData proto.AuthRecoveryBeginResponseData
		_ = json.Unmarshal(begin.Data, &beginData)
		_, result, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/prepare", map[string]any{
			"alias": alias, "entered_recovery_key_handle": beginData.EnteredKeyHandle,
			"challenge_token": "c", "signature": "s", "wrapped_keeper_b64": wrappedOld,
			"recovery_key_version": recoverykey.Version, "new_recovery_key": "ZYXW-VUTS-RQPN-MLKJ-HGFE-DCBA",
			"account_id": routeOwner, "rotated_at": time.Now().Unix(),
		})
		return result, body
	}

	if result, body := prepare("BCDE-FGHJ-KLMN-PQRS-TUVW-XYZ2"); result.Success {
		t.Fatalf("a wrong RK24 prepared: %s", body)
	}
	if got := store.Snapshot(); !reflect.DeepEqual(got, before) {
		t.Fatal("a wrong RK24 changed the keyring")
	}

	result, _ := prepare(rk)
	if !result.Success {
		t.Fatal("prepare with the right RK24 failed")
	}
	var prep proto.AuthRecoveryPrepareResponseData
	_ = json.Unmarshal(result.Data, &prep)
	if code, aborted, body := callRoute(t, server, session, csrf, "/v1/auth/recovery/abort",
		map[string]string{"new_public_key": prep.NewPublicKey}); code != http.StatusOK || !aborted.Success {
		t.Fatalf("abort: %d %s", code, body)
	}
	if got := store.Snapshot(); !reflect.DeepEqual(got, before) {
		t.Fatal("abort did not restore the keyring")
	}
}

// The App reaches the group DEK wraps only in their pin-enforced form.
func TestAppGroupDEKRoutesAlwaysEnforcePins(t *testing.T) {
	server := newTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	own := routeKeypair(t)
	_ = keychain.SavePrivateKey(store, own.PrivateKey)
	_ = keychain.SavePublicKey(store, own.PublicKey)
	session, csrf := openTestSession(t, server)
	peer := routeKeypair(t)
	archive := routeKeypair(t)
	stranger := routeKeypair(t)
	groupDEK := bytes.Repeat([]byte{0x44}, 32)
	wrappedForMe := wrapTo(t, own.PublicKey, groupDEK)

	// generate wraps to this Keeper's own key, whatever the caller wants.
	code, generated, body := callRoute(t, server, session, csrf, "/v1/group-dek/generate", map[string]any{})
	if code != http.StatusOK || !generated.Success {
		t.Fatalf("generate: %d %s", code, body)
	}
	var gen proto.GroupDEKGenerateAndOpenResponseData
	_ = json.Unmarshal(generated.Data, &gen)
	if len(openWith(t, own.PrivateKey, gen.EncryptedForMeB64)) != 32 {
		t.Fatal("generated DEK is not wrapped to the own key")
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/group-dek/generate",
		map[string]string{"my_public_key": stranger.PublicKey}); code != http.StatusBadRequest {
		t.Fatalf("generate took a caller key: %d", code)
	}
	if code, closed, _ := callRoute(t, server, session, csrf, "/v1/group-dek/close",
		map[string]string{"group_handle": gen.GroupHandle}); code != http.StatusOK || !closed.Success {
		t.Fatalf("close: %d", code)
	}

	member := map[string]any{
		"wrapped_for_me_b64": wrappedForMe, "other_public_key": peer.PublicKey,
		"owner_account_id": routeOwner, "other_account_id": routePeer,
	}
	code, result, body := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-member", member)
	if code != http.StatusOK || !result.Success || !strings.Contains(string(result.Data), `"pin_enforced":true`) {
		t.Fatalf("member rewrap: %d %s", code, body)
	}
	var memberData struct {
		EncryptedForOtherB64 string `json:"encrypted_for_other_b64"`
	}
	_ = json.Unmarshal(result.Data, &memberData)
	if !bytes.Equal(openWith(t, peer.PrivateKey, memberData.EncryptedForOtherB64), groupDEK) {
		t.Fatal("member rewrap did not reach the peer")
	}
	for _, missing := range []string{"owner_account_id", "other_account_id"} {
		without := map[string]any{}
		for key, value := range member {
			if key != missing {
				without[key] = value
			}
		}
		if code, _, _ := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-member", without); code != http.StatusBadRequest {
			t.Fatalf("member rewrap without %s: %d", missing, code)
		}
	}

	// The peer's key changes with no chain: the pin refuses and nothing is wrapped.
	changed := map[string]any{}
	for key, value := range member {
		changed[key] = value
	}
	changed["other_public_key"] = stranger.PublicKey
	code, result, body = callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-member", changed)
	if code != http.StatusOK || result.Success || result.ErrorCode != "peer_key_changed" || strings.Contains(body, "encrypted_for_other") {
		t.Fatalf("changed key: %d %s", code, body)
	}

	many := func(recipients []map[string]any, extra map[string]any) (int, routeResult, string) {
		payload := map[string]any{
			"wrapped_for_me_b64": wrappedForMe, "owner_account_id": routeOwner, "recipients": recipients,
		}
		for key, value := range extra {
			payload[key] = value
		}
		return callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-many", payload)
	}
	code, result, body = many([]map[string]any{
		{"public_key": own.PublicKey},
		{"account_id": routePeer, "public_key": peer.PublicKey},
		{"public_key": archive.PublicKey, "org_archive": true},
	}, nil)
	if code != http.StatusOK || !result.Success {
		t.Fatalf("many: %d %s", code, body)
	}
	refusals := map[string][]map[string]any{
		"an exempt stranger":         {{"public_key": stranger.PublicKey}},
		"two archive keys":           {{"public_key": archive.PublicKey, "org_archive": true}, {"public_key": stranger.PublicKey, "org_archive": true}},
		"an archive-flagged account": {{"account_id": routePeer, "public_key": peer.PublicKey, "org_archive": true}},
		"no recipients":              {},
	}
	for name, recipients := range refusals {
		if code, _, _ := many(recipients, nil); code != http.StatusBadRequest {
			t.Fatalf("many with %s: %d", name, code)
		}
	}
	if code, _, _ := many([]map[string]any{{"account_id": routePeer, "public_key": peer.PublicKey}},
		map[string]any{"recipient_public_keys": []string{stranger.PublicKey}}); code != http.StatusBadRequest {
		t.Fatalf("the unenforced recipient list was accepted: %d", code)
	}
}

// The wrap routes carry pin context (rotation chains, transparency proofs)
// far past the 8 KiB every other route keeps.
func TestAppGroupDEKRoutesTakeTheirOwnSizeCap(t *testing.T) {
	server := newTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	own := routeKeypair(t)
	_ = keychain.SavePrivateKey(store, own.PrivateKey)
	_ = keychain.SavePublicKey(store, own.PublicKey)
	session, csrf := openTestSession(t, server)
	recipients := []map[string]any{}
	for i := 0; i < 24; i++ {
		recipients = append(recipients, map[string]any{
			"account_id": "33333333-3333-4333-8333-" + strings.Repeat("0", 10) + string(rune('a'+i/10)) + string(rune('0'+i%10)),
			"public_key": routeKeypair(t).PublicKey,
		})
	}
	payload := map[string]any{
		"wrapped_for_me_b64": wrapTo(t, own.PublicKey, bytes.Repeat([]byte{1}, 32)),
		"owner_account_id":   routeOwner, "recipients": recipients,
	}
	raw, _ := json.Marshal(payload)
	if len(raw) <= maxRequestBytes {
		t.Fatalf("payload %d is not past the default cap", len(raw))
	}
	if code, result, body := callRoute(t, server, session, csrf, "/v1/group-dek/rewrap-for-many", payload); code != http.StatusOK || !result.Success {
		t.Fatalf("large rewrap: %d %s", code, body)
	}
	if code, _, _ := callRoute(t, server, session, csrf, "/v1/auth/recovery/begin", map[string]string{
		"alias": strings.Repeat("a", maxRequestBytes), "recovery_key": "x",
	}); code != http.StatusBadRequest {
		t.Fatalf("an oversized recovery request was accepted: %d", code)
	}
}
