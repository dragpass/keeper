// Tests for HandleMLSKeyPackageGenerate. The permit gate runs in every build;
// the KeyPackages themselves only where the MLS library is linked, and the
// default build answers CHAT_MLS_CAPABILITY_REQUIRED instead.
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func (f *chatStateFixture) keyPackages(t *testing.T, p proto.ChatStatePermit, count int) proto.BaseResponse {
	t.Helper()
	raw, err := json.Marshal(proto.MLSKeyPackageGenerateRequest{
		Permit: p, OrgID: chatOrgID, ConversationID: chatConvID, Count: count,
	})
	if err != nil {
		t.Fatal(err)
	}
	return HandleMLSKeyPackageGenerate(f.deps, raw)
}

// enrollAccount gives the fixture's keyring an account keypair and a leaf
// declared for accountID, through a challenge the fixture's server key signed.
func (f *chatStateFixture) enrollAccount(t *testing.T, accountID string) {
	t.Helper()
	seedActiveKeypairForRotateTest(t, f.deps.Store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.AccountID = accountID
	req.NotBefore = f.clock.now().Unix()
	req.NotAfter = req.NotBefore + proto.MLSLeafMaxValiditySeconds
	req.ChallengeToken = leafChallenge(accountID, req.DeviceID, f.clock.now().Unix()+proto.MLSLeafChallengeTTLSeconds)
	sig, err := crypto.SignData(f.key, req.ChallengeToken)
	if err != nil {
		t.Fatal(err)
	}
	req.ServerSignature = base64.StdEncoding.EncodeToString(sig)
	req.ServerKeyVersion = msgServerKeyVersion
	decl := declareLeaf(t, f.deps, req)
	accept := acceptanceFor(decl)
	sig, err = crypto.SignData(f.key, accept.AcceptanceToken)
	if err != nil {
		t.Fatal(err)
	}
	accept.ServerSignature = base64.StdEncoding.EncodeToString(sig)
	accept.ServerKeyVersion = msgServerKeyVersion
	if resp := HandleMLSLeafPromote(f.deps, accept); !resp.Success {
		t.Fatalf("promote: %s", resp.Error)
	}
}

func TestMLSKeyPackageGenerate_TheGateRunsFirst(t *testing.T) {
	f := newChatStateFixture(t)
	unsigned := f.unsignedPermit()
	unsigned.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
	if resp := f.keyPackages(t, unsigned, 1); resp.ErrorCode != proto.ChatStateErrorCodeNotAuthorized {
		t.Fatalf("unsigned permit: %q", resp.ErrorCode)
	}
	for _, count := range []int{0, proto.MLSKeyPackageGenerateMaxCount + 1} {
		if resp := f.keyPackages(t, f.permit(t), count); resp.ErrorCode != proto.ChatStateErrorCodeInvalidInput {
			t.Fatalf("count %d: %q", count, resp.ErrorCode)
		}
	}
	f.assertStateRootAbsent(t)
}

func TestMLSKeyPackageGenerate_ProducesKeyPackagesOrSaysTheLibraryIsMissing(t *testing.T) {
	f := newChatStateFixture(t)
	f.enrollAccount(t, chatAccountID)

	resp := f.keyPackages(t, f.permit(t), 3)
	if !mls.Available() {
		if resp.ErrorCode != proto.ChatMLSErrorCodeCapabilityRequired {
			t.Fatalf("without the library: %+v", resp)
		}
		return
	}
	if !resp.Success {
		t.Fatalf("generate: %s", resp.Error)
	}
	data := resp.Data.(proto.MLSKeyPackageGenerateResponseData)
	if len(data.KeyPackages) != 3 {
		t.Fatalf("%d key packages", len(data.KeyPackages))
	}
	now := uint64(time.Unix(chatNowUnix, 0).Unix())
	for _, kp := range data.KeyPackages {
		raw, err := base64.StdEncoding.DecodeString(kp.KeyPackageB64)
		if err != nil || len(raw) == 0 || len(raw) > mls.MaxKeyPackageBytes {
			t.Fatalf("key package of %d bytes, %v", len(raw), err)
		}
		// mls-rs stamps the lifetime from the wall clock, not the fixture's.
		if kp.NotAfter <= now {
			t.Fatalf("not_after %d is in the past", kp.NotAfter)
		}
	}
	f.assertStateRootAbsent(t)
}

// A permit for one account must not mint KeyPackages for another account's
// leaf.
func TestMLSKeyPackageGenerate_RefusesAPermitForAnotherAccount(t *testing.T) {
	if !mls.Available() {
		t.Skip("the account check runs after the library check")
	}
	f := newChatStateFixture(t)
	f.enrollAccount(t, leafTestAccountID) // not the permit's chatAccountID

	if resp := f.keyPackages(t, f.permit(t), 1); resp.ErrorCode != proto.ChatStateErrorCodeNotAuthorized {
		t.Fatalf("another account's permit: %+v", resp)
	}
}
