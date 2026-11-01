package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func personalDisplayPrepareFixture(t *testing.T) (Deps, proto.PersonalDisplayPrepareRequest, proto.PersonalDEKBindRequest, *ecdsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	d, _, binding, serverKey := personalBindingFixture(t)
	d.GroupDisplayChallenges = NewGroupDisplayChallengeStore()
	d.DisplayTokens = testDisplayTokens{}
	aad := "test.display-token|personal|1|||0"
	encrypted := HandleDEKUnwrapAndEncryptWithAAD(d, proto.DEKUnwrapAndEncryptWithAADRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("frame-only-test-text")),
		AADB64:       base64.StdEncoding.EncodeToString([]byte(aad)),
	})
	if !encrypted.Success {
		t.Fatal("personal ciphertext fixture failed")
	}
	value := encrypted.Data.(proto.DEKUnwrapAndEncryptResponseData)
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return d, proto.PersonalDisplayPrepareRequest{
		Token: "selected personal token", TokenAADB64: base64.StdEncoding.EncodeToString([]byte(aad)),
		IVB64: value.IVB64, CiphertextB64: value.CiphertextB64,
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               "44444444-4444-4444-8444-444444444444",
		SessionIssuedAtNanos:  "1793440000000000000",
	}, binding, frameKey, serverKey
}

func TestPersonalDisplayPrepareRequiresBoundProvenance(t *testing.T) {
	d, req, binding, _, _ := personalDisplayPrepareFixture(t)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if HandlePersonalDisplayPrepare(d, payload).Success {
		t.Fatal("unproven personal slot minted a display challenge")
	}
	if !HandlePersonalDEKBind(d, binding).Success {
		t.Fatal("provenance fixture bind failed")
	}
	response := HandlePersonalDisplayPrepare(d, payload)
	if !response.Success {
		t.Fatal("verified personal slot did not mint a display challenge")
	}
	data, ok := response.Data.(proto.PersonalDisplayPrepareResponseData)
	if !ok || data.WrapDigest != binding.Proof.WrappedDEKDigest || data.Challenge == "" ||
		data.OperationDigest == "" || data.FrameKeyDigest == "" {
		t.Fatal("prepare response lost the current provenance or operation binding")
	}
}
