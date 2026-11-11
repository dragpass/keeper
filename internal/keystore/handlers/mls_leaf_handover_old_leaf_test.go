package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const handoverTestNewDevice = "77777777-4444-4444-8444-444444444444"

// handoverSignRequest is a handover request naming oldFP as the leaf that
// signs, for a declaration of another device the account key signed. It is
// decoded from JSON the way the dispatcher decodes it.
func handoverSignRequest(t *testing.T, accountKey *crypto.KeyPair, oldFP string) proto.MLSLeafHandoverSignRequest {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := crypto.MLSLeafSignatureKeyFingerprint(public)
	now := time.Now().Unix()
	decl := proto.MLSLeafDeclaration{
		AccountID: leafTestAccountID, DeviceID: handoverTestNewDevice,
		SignatureKey: base64.StdEncoding.EncodeToString(public), SignatureKeyFingerprint: fp,
		NotBefore: now, NotAfter: now + 86400, Reason: proto.MLSLeafReasonRotate,
	}
	priv, err := crypto.ParsePrivateKey(accountKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignData(priv, decl.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	decl.Signature = base64.StdEncoding.EncodeToString(sig)
	raw, _ := json.Marshal(map[string]any{
		"account_id": leafTestAccountID, "new_declaration": decl, "expires_at": now + 300,
		"old_signature_key_fingerprint": oldFP,
	})
	var req proto.MLSLeafHandoverSignRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func seedHandoverActiveLeaf(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveMLSLeafKey(store, keychain.MLSLeafKey{
		AccountID: leafTestAccountID, DeviceID: leafTestDeviceID, SecretKey: secret, PublicKey: public,
		Declaration: []byte("declaration"),
	}); err != nil {
		t.Fatal(err)
	}
	fp, _ := crypto.MLSLeafSignatureKeyFingerprint(public)
	return fp
}

// lv78 old leaf binding: the handover is signed only by the leaf the request
// names, checked under the leaf lock where the signing key is read. A leaf
// that changed since the request was prepared signs nothing.
func TestHandleMLSLeafHandoverSign_SignsOnlyWithTheNamedActiveLeaf(t *testing.T) {
	deps, _, store := newTestDeps(t)
	_, accountKey := seedActiveKeypairForRotateTest(t, store)
	named := seedHandoverActiveLeaf(t, store)

	resp := HandleMLSLeafHandoverSign(deps, handoverSignRequest(t, accountKey, named))
	data, ok := resp.Data.(proto.MLSLeafHandoverSignResponseData)
	if !resp.Success || !ok || data.Handover.OldSignatureKeyFP != named {
		t.Fatalf("a handover by the named leaf: %+v", resp)
	}

	seedHandoverActiveLeaf(t, store)
	resp = HandleMLSLeafHandoverSign(deps, handoverSignRequest(t, accountKey, named))
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeChatMLSHandoverInvalid) {
		t.Fatalf("a handover naming a leaf that is no longer active: %+v", resp)
	}
}
