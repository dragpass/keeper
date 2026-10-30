package handlers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/onlineauth"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestGroupOnlineExecuteVerifiesAndConsumesBeforeClipboard(t *testing.T) {
	f := newAuditFixture(t)
	context := *f.gc
	context.Policy = proto.GrantPolicyLegacy
	handle := f.openWith(t, f.wrapToMe(t, f.pubPEM, &context), &context)
	deviceID := "11111111-1111-4111-8111-111111111111"
	if _, _, err := keychain.EnsureDeviceID(f.store, func() (string, keychain.DeviceIDSource, error) {
		return deviceID, keychain.DeviceIDGenerated, nil
	}); err != nil {
		t.Fatal(err)
	}
	gate, err := onlineauth.NewGroup(f.deps.ServerKeyVerifier, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	f.deps.GroupOnline = gate
	sealed := HandleGroupEncrypt(f.deps, proto.GroupEncryptRequest{GroupHandle: handle,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("online-group-fixture"))})
	if !sealed.Success {
		t.Fatal("fixture encryption failed")
	}
	data := sealed.Data.(proto.GroupEncryptResponseData)
	request := proto.GroupDecryptToClipboardRequest{GroupHandle: handle, IVB64: data.IVB64,
		CiphertextB64: data.CiphertextB64, ClipboardTTLMs: 10000}
	tokenID := "22222222-2222-4222-8222-222222222222"
	prepared := HandleGroupOnlinePrepare(f.deps, proto.GroupOnlinePrepareRequest{TokenID: tokenID, Request: request})
	if !prepared.Success {
		t.Fatal("current group request could not prepare")
	}
	var challenge struct {
		Challenge   string `json:"challenge"`
		Commitment  string `json:"commitment"`
		GrantDigest string `json:"grant_digest"`
	}
	encoded, _ := json.Marshal(prepared.Data)
	if err := json.Unmarshal(encoded, &challenge); err != nil {
		t.Fatal(err)
	}
	now := f.clock.now()
	decision := onlineauth.GroupDecision{TokenID: tokenID, Action: proto.ActionGroupDecryptToClipboard,
		Challenge: challenge.Challenge, Commitment: challenge.Commitment, GrantDigest: challenge.GrantDigest,
		AccountID: f.v.AccountID, DeviceID: deviceID, OrgID: context.OrgID, GroupID: context.GroupID,
		DEKVersion: context.DekVersion, GrantPolicy: context.Policy, Client: "extension", SessionStartNanos: 42,
		IssuedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(15 * time.Second).UnixMilli(), ServerKeyVersion: 1}
	decision.Signature = f.sign(t, decision.Canonical())
	input := proto.GroupOnlineExecuteRequest{TokenID: tokenID, Request: request, Decision: decision}
	if response := HandleGroupOnlineExecute(f.deps, input); !response.Success {
		t.Fatal("valid online decision did not copy")
	}
	if response := HandleGroupOnlineExecute(f.deps, input); response.Success {
		t.Fatal("replayed online decision copied")
	}
	if f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 1 {
		t.Fatal("online decision did not write exactly once")
	}
}
