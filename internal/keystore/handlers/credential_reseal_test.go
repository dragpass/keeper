// Tests for the credential payload reseal carried by the tracked encrypt
// actions (lv84, docs/protocol.md "Credential payload reseal"). Test values
// are compared in memory and never printed.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// openResealed opens a resealed payload the way a credential sink does and
// returns its parsed shape. aad is the canonical credential AAD.
func openResealed(t *testing.T, dek []byte, p *proto.CredentialPayloadSealed, aad string) sealedCredential {
	t.Helper()
	if p == nil {
		t.Fatal("no credential payload in the response")
	}
	iv, err1 := base64.StdEncoding.DecodeString(p.IVB64)
	ct, err2 := base64.StdEncoding.DecodeString(p.CiphertextB64)
	if err1 != nil || err2 != nil {
		t.Fatal("payload is not base64")
	}
	pt, err := crypto.OpenAESGCM(dek, iv, ct, []byte(aad))
	if err != nil {
		t.Fatal("payload does not open under the canonical credential AAD")
	}
	var cred sealedCredential
	if err := json.Unmarshal(pt, &cred); err != nil {
		t.Fatal("payload is not a credential")
	}
	sum := sha256.Sum256([]byte(aad))
	if p.AADHashB64 != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatal("aad hash does not describe the canonical AAD")
	}
	return cred
}

func wantBearerToken(t *testing.T, cred sealedCredential, value string) {
	t.Helper()
	if cred.Type != "api_key" || cred.Secret["authorization_scheme"] != "Bearer" || cred.Secret["token"] != value ||
		len(cred.Secret) != 2 {
		t.Fatal("resealed payload is not the api_key Bearer shape holding the encrypted value")
	}
}

func TestGroupEncryptBoundTracked_ResealsTheCredentialPayloadFromTheSameValue(t *testing.T) {
	f := newBoundGroupFixture(t)
	req := f.trackedReq(`va"lue\one`, nil)
	req.SealCredentialPayload = true
	data := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, req))
	if data.CredentialPayload == nil || data.CredentialPayload.DekVersion != 7 {
		t.Fatal("payload missing or not sealed under the token's DEK version")
	}
	cred := openResealed(t, f.raw, data.CredentialPayload, boundOrg+"|"+trackEntry+"|credential|1|7")
	wantBearerToken(t, cred, `va"lue\one`)
}

func TestGroupEncryptBoundTracked_NoPayloadUnlessAsked(t *testing.T) {
	f := newBoundGroupFixture(t)
	data := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq("value-one", nil)))
	if data.CredentialPayload != nil {
		t.Fatal("payload sealed without seal_credential_payload")
	}
}

// A value that is not UTF-8 cannot be carried in the JSON payload without
// changing it, so no payload is sealed; the token and record still are.
func TestGroupEncryptBoundTracked_NonUTF8ValueIsNotResealed(t *testing.T) {
	f := newBoundGroupFixture(t)
	req := f.trackedReq("x", nil)
	req.PlaintextB64 = base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 'a'})
	req.SealCredentialPayload = true
	data := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, req))
	if data.CredentialPayload != nil || data.CiphertextB64 == "" || data.ChangeRecord.Seq != 1 {
		t.Fatal("want token and record without a payload")
	}
	// The caller learns why, so the server can name a recovery that works.
	if data.CredentialPayloadSkipped != "unsupported_value" {
		t.Fatalf("skipped reason %q, want unsupported_value", data.CredentialPayloadSkipped)
	}
}

func TestDEKUnwrapAndEncryptBoundTracked_ResealsUnderTheAccountScope(t *testing.T) {
	deps, _, _, wrapped, dek := newBoundPersonalFixture(t)
	req := personalTrackedReq(wrapped, "value-two", nil)
	req.SealCredentialPayload = true
	data := personalTrackedData(t, HandleDEKUnwrapAndEncryptBoundTracked(deps, req))
	if data.CredentialPayload == nil || data.CredentialPayload.DekVersion != 1 {
		t.Fatal("personal payload missing or not at version 1")
	}
	cred := openResealed(t, dek, data.CredentialPayload, boundAccount+"|"+trackEntry+"|credential|1|1")
	wantBearerToken(t, cred, "value-two")
}
