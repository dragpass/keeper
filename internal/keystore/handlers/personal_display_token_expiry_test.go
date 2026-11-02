package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A token that expires while the execute request is in flight must not be
// opened, even under a still-valid display decision.
func TestPersonalDisplayExecuteRechecksTokenExpiryAtOpen(t *testing.T) {
	d, req, binding, _, serverKey := personalDisplayPrepareFixture(t)
	if !HandlePersonalDEKBind(d, binding).Success {
		t.Fatal("provenance fixture bind failed")
	}
	start := d.Now()
	expiry := strconv.FormatInt(start.Unix()+2, 10)
	encrypted := HandleDEKUnwrapAndEncryptBound(d, proto.DEKUnwrapAndEncryptBoundRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("frame-only-test-text")),
		TokenExpiry:  expiry,
	})
	if !encrypted.Success {
		t.Fatal("expiring ciphertext fixture failed")
	}
	sealed := encrypted.Data.(proto.DEKUnwrapAndEncryptResponseData)
	req.TokenExpiry = expiry
	req.IVB64, req.CiphertextB64 = sealed.IVB64, sealed.CiphertextB64
	payload, _ := json.Marshal(req)
	prepared := HandlePersonalDisplayPrepare(d, payload)
	if !prepared.Success {
		t.Fatalf("prepare: %s", prepared.Error)
	}
	p := prepared.Data.(proto.PersonalDisplayPrepareResponseData)
	decision := proto.PersonalDisplayDecision{
		Challenge: p.Challenge, AccountID: binding.Proof.AccountID,
		DeviceID: binding.Proof.DeviceID, TokenID: req.TokenID,
		SessionIssuedAtNanos: 1793440000000000000,
		WrapDigest:           p.WrapDigest, OperationDigest: p.OperationDigest,
		FrameKeyDigest: p.FrameKeyDigest, IssuedAt: start.Unix(), ExpiresAt: start.Unix() + 10,
		ServerKeyVersion: 1,
	}
	sig, err := keepercrypto.SignData(serverKey, proto.PersonalDisplayDecisionCanonical(decision))
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(sig)
	// Each clock read advances one second: admission at entry still sees an
	// unexpired token, while the read just before opening sees it expired.
	tick := start
	d.Clock = func() time.Time {
		tick = tick.Add(time.Second)
		return tick
	}
	encoded, _ := json.Marshal(proto.PersonalDisplayExecuteRequest{Prepare: req, Decision: decision})
	if HandlePersonalDisplayExecute(d, encoded).Success {
		t.Fatal("token that expired during execution produced an envelope")
	}
}
