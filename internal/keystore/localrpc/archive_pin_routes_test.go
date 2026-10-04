package localrpc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// Quorum combine on the App route takes only pin-carrying recipients, each
// naming its account; Keeper judges them before it reassembles anything.
func TestArchiveQuorumCombineRouteTakesOnlyPinnedRecipients(t *testing.T) {
	server, _ := newChatTestServer(t)
	store := server.app.Store.(*testdouble.MemorySecretStore)
	session, csrf := openTestSession(t, server)

	archive := routeKeypair(t)
	_ = keychain.SaveArchivePrivateKey(store, archive.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archive.PublicKey)
	admins := []*crypto.KeyPair{routeKeypair(t), routeKeypair(t)}
	split := server.app.HandleRequest([]byte(`{"action":"archive_key_split","payload":` + mustJSON(t, proto.ArchiveKeySplitRequest{
		ThresholdN: 2, RecipientPublicKeys: []string{admins[0].PublicKey, admins[1].PublicKey},
	}) + `}`))
	if !split.Success {
		t.Fatalf("split: %+v", split)
	}
	var splitData proto.ArchiveKeySplitResponseData
	_ = remarshal(split.Data, &splitData)
	begun := server.app.HandleRequest([]byte(`{"action":"archive_session_begin"}`))
	var sessionData proto.ArchiveSessionBeginResponseData
	_ = remarshal(begun.Data, &sessionData)
	sessionPub, _ := crypto.ParsePublicKey(sessionData.SessionPublicKey)
	shares := make([]map[string]string, 2)
	for i, admin := range admins {
		private, _ := crypto.ParsePrivateKey(admin.PrivateKey)
		raw, err := crypto.HybridUnwrap(private, splitData.Shares[i].WrappedKey, splitData.Shares[i].Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		wrappedKey, ciphertext, _ := crypto.HybridWrap(sessionPub, raw)
		shares[i] = map[string]string{"wrapped_key": wrappedKey, "ciphertext": ciphertext}
	}
	archivePub, _ := crypto.ParsePublicKey(archive.PublicKey)
	wrappedOld, _ := crypto.EncryptData(archivePub, make([]byte, 32))
	member, stranger := routeKeypair(t), routeKeypair(t)
	combine := func(extra map[string]any) (int, routeResult, string) {
		payload := map[string]any{
			"rewrapped_shares":    shares,
			"wrapped_old_dek_b64": base64.StdEncoding.EncodeToString(wrappedOld),
		}
		for key, value := range extra {
			payload[key] = value
		}
		return callRoute(t, server, session, csrf, "/v1/archive/archive_quorum_combine_and_rewrap", payload)
	}
	pinned := func(key string) map[string]any {
		return map[string]any{
			"owner_account_id": routeOwner,
			"recipients":       []map[string]any{{"account_id": routePeer, "public_key": key}},
		}
	}
	if code, result, body := combine(pinned(member.PublicKey)); code != http.StatusOK || !result.Success {
		t.Fatalf("pinned combine: %d %s", code, body)
	}
	if code, result, body := combine(pinned(stranger.PublicKey)); code != http.StatusOK || result.ErrorCode != "peer_key_changed" || strings.Contains(body, "encrypted_group_dek") {
		t.Fatalf("combine to a changed key: %d %s", code, body)
	}
	for name, extra := range map[string]map[string]any{
		"the flat list":        {"recipient_public_keys": []string{member.PublicKey}},
		"no owner":             {"recipients": []map[string]any{{"account_id": routePeer, "public_key": member.PublicKey}}},
		"an unnamed recipient": {"owner_account_id": routeOwner, "recipients": []map[string]any{{"public_key": member.PublicKey}}},
		"no recipients":        {"owner_account_id": routeOwner, "recipients": []map[string]any{}},
	} {
		if code, _, _ := combine(extra); code != http.StatusBadRequest {
			t.Fatalf("combine with %s: %d", name, code)
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
