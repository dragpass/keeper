// mls_chat_test.go — the MLS chat actions' gate and error mapping, in the
// default build. What these assert holds whether or not the MLS library is
// linked: an unauthorized or malformed request never opens the state
// directory, and every chatstate or mls failure reaches the caller under the
// code the protocol names for it. The real MLS paths are exercised end to end
// in dispatch, under -tags mls.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	mlsTestCommitID = "77777777-7777-4777-8777-777777777777"
	mlsTestPeer     = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	mlsTestDevice   = "d1111111-1111-4111-8111-111111111111"
)

var mlsTestBlobB64 = base64.StdEncoding.EncodeToString([]byte("not an mls message"))

type mlsChatCase struct {
	action  string
	handler func(Deps, json.RawMessage) proto.BaseResponse
	request func(p proto.ChatStatePermit) any
}

// mlsChatCases is one well-formed request per action. "Well-formed" is only
// structural: none of these would get past MLS, which is the point — a
// refusal below has to come from the gate, before anything looks at a byte.
func mlsChatCases() []mlsChatCase {
	member := []proto.MLSMemberKeyPackage{{AccountID: mlsTestPeer, DeviceID: mlsTestDevice, KeyPackageB64: mlsTestBlobB64}}
	return []mlsChatCase{
		{proto.MLSGroupCreate, HandleMLSGroupCreate, func(p proto.ChatStatePermit) any {
			return proto.MLSGroupCreateRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				ClientCommitID: mlsTestCommitID, Members: member,
			}
		}},
		{proto.MLSCommitBuild, HandleMLSCommitBuild, func(p proto.ChatStatePermit) any {
			return proto.MLSCommitBuildRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				ClientCommitID: mlsTestCommitID, ExpectedEpoch: 1, UpdateSelf: true,
			}
		}},
		{proto.MLSCommitConfirm, HandleMLSCommitConfirm, func(p proto.ChatStatePermit) any {
			return proto.MLSCommitConfirmRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				ClientCommitID: mlsTestCommitID, Outcome: proto.MLSCommitOutcomeAccepted,
			}
		}},
		{proto.MLSProcess, HandleMLSProcess, func(p proto.ChatStatePermit) any {
			return proto.MLSProcessRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				Seq: 4, Epoch: 2, CommitB64: mlsTestBlobB64,
			}
		}},
		{proto.MLSJoin, HandleMLSJoin, func(p proto.ChatStatePermit) any {
			return proto.MLSJoinRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID, WelcomeB64: mlsTestBlobB64,
			}
		}},
		{proto.MLSEncrypt, HandleMLSEncrypt, func(p proto.ChatStatePermit) any {
			return proto.MLSEncryptRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				ClientMessageID: mlsTestCommitID, ExpectedEpoch: 1,
				PlaintextB64: base64.StdEncoding.EncodeToString([]byte("hello")),
			}
		}},
		{proto.MLSConversationStatus, HandleMLSConversationStatus, func(p proto.ChatStatePermit) any {
			return proto.MLSConversationStatusRequest{Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID}
		}},
		{proto.MLSDecryptBatchForAppDisplay, HandleMLSDecryptBatchForAppDisplay, func(p proto.ChatStatePermit) any {
			return proto.MLSDecryptBatchForAppDisplayRequest{
				Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
				Messages: []proto.MLSDisplayMessage{{Seq: 3, CiphertextB64: mlsTestBlobB64}},
			}
		}},
	}
}

func TestMLSChat_AnUnsignedPermitIsRefusedBeforeTheStateDirectoryExists(t *testing.T) {
	for _, tc := range mlsChatCases() {
		t.Run(tc.action, func(t *testing.T) {
			f := newChatStateFixture(t)
			forged := f.permit(t)
			forged.PendingRemovalAccountIDs = []string{mlsTestPeer}
			resp := tc.handler(f.deps, chatMarshal(t, tc.request(forged)))
			assertChatStateFailure(t, resp, proto.ChatStateErrorCodeNotAuthorized)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestMLSChat_APermitForAnotherConversationIsRefused(t *testing.T) {
	for _, tc := range mlsChatCases() {
		t.Run(tc.action, func(t *testing.T) {
			f := newChatStateFixture(t)
			p := f.unsignedPermit()
			p.ConversationID = mlsTestPeer
			var raw map[string]any
			if err := json.Unmarshal(chatMarshal(t, tc.request(f.sign(t, p))), &raw); err != nil {
				t.Fatal(err)
			}
			raw["conversation_id"] = chatConvID
			resp := tc.handler(f.deps, chatMarshal(t, raw))
			assertChatStateFailure(t, resp, proto.ChatStateErrorCodeNotAuthorized)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestMLSChat_AnExpiredPermitIsRefused(t *testing.T) {
	for _, tc := range mlsChatCases() {
		t.Run(tc.action, func(t *testing.T) {
			f := newChatStateFixture(t)
			p := f.permit(t)
			f.clock.unix += proto.ChatStatePermitTTLSeconds
			assertChatStateFailure(t, tc.handler(f.deps, chatMarshal(t, tc.request(p))),
				proto.ChatStateErrorCodeNotAuthorized)
			f.assertStateRootAbsent(t)
		})
	}
}

// Past the gate, the next refusal depends on the build: without the library
// it is CHAT_MLS_CAPABILITY_REQUIRED; with it, a device that never declared a
// leaf has no session to open. Neither leaves a group behind.
func TestMLSChat_AnAuthorizedRequestNeedsTheLibraryAndALeaf(t *testing.T) {
	for _, tc := range mlsChatCases() {
		t.Run(tc.action, func(t *testing.T) {
			f := newChatStateFixture(t)
			resp := tc.handler(f.deps, chatMarshal(t, tc.request(f.permit(t))))
			if mls.Available() {
				assertChatStateFailure(t, resp, proto.ChatMLSErrorCodeFailed)
				if !strings.Contains(resp.Error, "leaf") {
					t.Fatalf("error = %q; want the missing leaf named", resp.Error)
				}
				return
			}
			assertChatStateFailure(t, resp, proto.ChatMLSErrorCodeCapabilityRequired)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestMLSChat_AnOversizedRequestIsRefusedByLength(t *testing.T) {
	for _, tc := range mlsChatCases() {
		t.Run(tc.action, func(t *testing.T) {
			f := newChatStateFixture(t)
			payload := make([]byte, proto.MLSChatMaxRequestBytes+1)
			for i := range payload {
				payload[i] = ' '
			}
			assertChatStateFailure(t, tc.handler(f.deps, payload), proto.ChatStateErrorCodeInvalidInput)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestMLSChat_ValidationRefusesMalformedRequests(t *testing.T) {
	f := newChatStateFixture(t)
	p := f.permit(t)
	build := func(mut func(*proto.MLSCommitBuildRequest)) proto.MLSCommitBuildRequest {
		r := proto.MLSCommitBuildRequest{
			Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
			ClientCommitID: mlsTestCommitID, ExpectedEpoch: 1, UpdateSelf: true,
		}
		mut(&r)
		return r
	}
	member := proto.MLSMemberKeyPackage{AccountID: mlsTestPeer, DeviceID: mlsTestDevice, KeyPackageB64: mlsTestBlobB64}
	oversized := base64.StdEncoding.EncodeToString(make([]byte, proto.MLSChatMaxKeyPackageBytes+1))
	cases := map[string]any{
		"two kinds": build(func(r *proto.MLSCommitBuildRequest) {
			r.RemoveAccountIDs = []string{mlsTestPeer}
		}),
		"no kind":    build(func(r *proto.MLSCommitBuildRequest) { r.UpdateSelf = false }),
		"epoch zero": build(func(r *proto.MLSCommitBuildRequest) { r.ExpectedEpoch = 0 }),
		"empty add":  build(func(r *proto.MLSCommitBuildRequest) { r.UpdateSelf, r.Add = false, []proto.MLSMemberKeyPackage{} }),
		"duplicate add": build(func(r *proto.MLSCommitBuildRequest) {
			r.UpdateSelf, r.Add = false, []proto.MLSMemberKeyPackage{member, member}
		}),
		"oversized key package": build(func(r *proto.MLSCommitBuildRequest) {
			r.UpdateSelf, r.Add = false, []proto.MLSMemberKeyPackage{{AccountID: mlsTestPeer, DeviceID: mlsTestDevice, KeyPackageB64: oversized}}
		}),
		"duplicate remove": build(func(r *proto.MLSCommitBuildRequest) {
			r.UpdateSelf, r.RemoveAccountIDs = false, []string{mlsTestPeer, mlsTestPeer}
		}),
		// The permit lists nobody as taken over, so a replace of anyone is a
		// replacement it has no key for.
		"replace of an unlisted account": build(func(r *proto.MLSCommitBuildRequest) {
			r.UpdateSelf, r.Replace = false, []proto.MLSReplaceMember{{AccountID: mlsTestPeer, KeyPackageB64: mlsTestBlobB64}}
		}),
		"empty replace": build(func(r *proto.MLSCommitBuildRequest) { r.UpdateSelf, r.Replace = false, []proto.MLSReplaceMember{} }),
	}
	listed := f.unsignedPermit()
	listed.PendingLeafReplacements = []proto.ChatStateLeafReplacement{
		{AccountID: mlsTestPeer, NewSignatureKeyFP: strings.Repeat("a", 64)},
	}
	lp := f.sign(t, listed)
	replace := []proto.MLSReplaceMember{{AccountID: mlsTestPeer, KeyPackageB64: mlsTestBlobB64}}
	withListed := func(mut func(*proto.MLSCommitBuildRequest)) proto.MLSCommitBuildRequest {
		r := proto.MLSCommitBuildRequest{
			Permit: lp, OrgID: lp.OrgID, ConversationID: lp.ConversationID,
			ClientCommitID: mlsTestCommitID, ExpectedEpoch: 1, Replace: replace,
		}
		mut(&r)
		return r
	}
	cases["replace with add"] = withListed(func(r *proto.MLSCommitBuildRequest) { r.Add = []proto.MLSMemberKeyPackage{member} })
	cases["replace with remove"] = withListed(func(r *proto.MLSCommitBuildRequest) { r.RemoveAccountIDs = []string{mlsTestPeer} })
	cases["replace with update"] = withListed(func(r *proto.MLSCommitBuildRequest) { r.UpdateSelf = true })
	cases["replace naming one account twice"] = withListed(func(r *proto.MLSCommitBuildRequest) {
		r.Replace = append(append([]proto.MLSReplaceMember(nil), replace...), replace...)
	})
	cases["replace with an oversized key package"] = withListed(func(r *proto.MLSCommitBuildRequest) {
		r.Replace = []proto.MLSReplaceMember{{AccountID: mlsTestPeer, KeyPackageB64: oversized}}
	})
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			assertChatStateFailure(t, HandleMLSCommitBuild(f.deps, chatMarshal(t, req)),
				proto.ChatStateErrorCodeInvalidInput)
		})
	}

	confirm := proto.MLSCommitConfirmRequest{
		Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
		ClientCommitID: mlsTestCommitID, Outcome: proto.MLSCommitOutcomeSuperseded,
	}
	assertChatStateFailure(t, HandleMLSCommitConfirm(f.deps, chatMarshal(t, confirm)),
		proto.ChatStateErrorCodeInvalidInput)
	confirm.Outcome, confirm.WinnerCommitB64 = proto.MLSCommitOutcomeAccepted, mlsTestBlobB64
	assertChatStateFailure(t, HandleMLSCommitConfirm(f.deps, chatMarshal(t, confirm)),
		proto.ChatStateErrorCodeInvalidInput)
	confirm.Outcome = "maybe"
	assertChatStateFailure(t, HandleMLSCommitConfirm(f.deps, chatMarshal(t, confirm)),
		proto.ChatStateErrorCodeInvalidInput)

	encrypt := proto.MLSEncryptRequest{
		Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID, ClientMessageID: mlsTestCommitID,
		ExpectedEpoch: 1, PlaintextB64: base64.StdEncoding.EncodeToString(make([]byte, proto.MLSEncryptMaxPlaintextBytes+1)),
	}
	assertChatStateFailure(t, HandleMLSEncrypt(f.deps, chatMarshal(t, encrypt)), proto.ChatStateErrorCodeInvalidInput)
	decrypt := proto.MLSDecryptBatchForAppDisplayRequest{
		Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
		Messages: []proto.MLSDisplayMessage{{Seq: 3, CiphertextB64: mlsTestBlobB64}, {Seq: 3, CiphertextB64: mlsTestBlobB64}},
	}
	assertChatStateFailure(t, HandleMLSDecryptBatchForAppDisplay(f.deps, chatMarshal(t, decrypt)), proto.ChatStateErrorCodeInvalidInput)
	decrypt.Messages = make([]proto.MLSDisplayMessage, proto.MLSDecryptMaxMessages+1)
	for i := range decrypt.Messages {
		decrypt.Messages[i] = proto.MLSDisplayMessage{Seq: uint64(i + 1), CiphertextB64: mlsTestBlobB64}
	}
	assertChatStateFailure(t, HandleMLSDecryptBatchForAppDisplay(f.deps, chatMarshal(t, decrypt)), proto.ChatStateErrorCodeInvalidInput)

	create := proto.MLSGroupCreateRequest{
		Permit: p, OrgID: p.OrgID, ConversationID: p.ConversationID,
		ClientCommitID: mlsTestCommitID, Members: make([]proto.MLSMemberKeyPackage, proto.MLSChatMaxMembersPerCommit+1),
	}
	assertChatStateFailure(t, HandleMLSGroupCreate(f.deps, chatMarshal(t, create)),
		proto.ChatStateErrorCodeInvalidInput)
	f.assertStateRootAbsent(t)
}

// The wire bounds are declared in proto, which cannot import the packages
// that enforce them.
func TestMLSChat_WireBoundsMatchTheLayersThatEnforceThem(t *testing.T) {
	if proto.MLSChatMaxMembersPerCommit != mls.MaxKeyPackagesPerCall {
		t.Errorf("members per commit %d != mls.MaxKeyPackagesPerCall %d",
			proto.MLSChatMaxMembersPerCommit, mls.MaxKeyPackagesPerCall)
	}
	if proto.MLSChatMaxKeyPackageBytes != mls.MaxKeyPackageBytes {
		t.Errorf("key package bytes %d != mls.MaxKeyPackageBytes %d",
			proto.MLSChatMaxKeyPackageBytes, mls.MaxKeyPackageBytes)
	}
	if proto.MLSChatMaxCommitBytes != chatstate.MaxCommitBytes {
		t.Errorf("commit bytes %d != chatstate.MaxCommitBytes %d",
			proto.MLSChatMaxCommitBytes, chatstate.MaxCommitBytes)
	}
	// The largest legal request of each kind fits under the cap, so the cap
	// refuses only what validation would refuse anyway.
	kp := base64.StdEncoding.EncodeToString(make([]byte, proto.MLSChatMaxKeyPackageBytes))
	commit := base64.StdEncoding.EncodeToString(make([]byte, proto.MLSChatMaxCommitBytes))
	if n := proto.MLSChatMaxMembersPerCommit*len(kp) + 64*1024; n > proto.MLSChatMaxRequestBytes {
		t.Errorf("a full member batch needs %d bytes, over the %d cap", n, proto.MLSChatMaxRequestBytes)
	}
	ct := base64.StdEncoding.EncodeToString(make([]byte, proto.ConversationCiphertextMaxBytes))
	if n := proto.MLSDecryptMaxMessages*(len(ct)+32) + 64*1024; n > proto.MLSDecryptMaxRequestBytes {
		t.Errorf("a full display batch needs %d bytes, over the %d cap", n, proto.MLSDecryptMaxRequestBytes)
	}
	if proto.ConversationCiphertextMaxBytes != chatstate.MaxCiphertextBytes {
		t.Errorf("display ciphertext bound %d != chatstate.MaxCiphertextBytes %d",
			proto.ConversationCiphertextMaxBytes, chatstate.MaxCiphertextBytes)
	}
	if proto.MLSDecryptMaxMessages != chatstate.MaxReceiveBatch {
		t.Errorf("display batch %d != chatstate.MaxReceiveBatch %d", proto.MLSDecryptMaxMessages, chatstate.MaxReceiveBatch)
	}
	if n := len(commit) + 64*1024; n > proto.MLSChatMaxRequestBytes {
		t.Errorf("a full commit needs %d bytes, over the %d cap", n, proto.MLSChatMaxRequestBytes)
	}
}

func TestMLSChat_FailuresMapToTheirProtocolCodes(t *testing.T) {
	f := newChatStateFixture(t)
	wrapped := func(err error) error { return fmt.Errorf("while testing: %w", err) }
	cases := []struct {
		err  error
		code string
	}{
		{mls.ErrLeafUntrusted, proto.ChatMLSErrorCodeLeafUntrusted},
		{&MLSLeafUntrustedError{Reason: "x"}, proto.ChatMLSErrorCodeLeafUntrusted},
		{chatstate.ErrRotationPending, proto.ChatMLSErrorCodeRotationPending},
		{chatstate.ErrLeafReplacementPending, proto.ChatMLSErrorCodeLeafReplacementPending},
		{chatstate.ErrReplacementNotListed, proto.ChatStateErrorCodeInvalidInput},
		{chatstate.ErrCommitPending, proto.ChatMLSErrorCodeCommitPending},
		{chatstate.ErrEpochStale, proto.ChatMLSErrorCodeEpochStale},
		{chatstate.ErrHandshakeApplied, proto.ChatMLSErrorCodeEpochStale},
		{chatstate.ErrHandshakeSkipped, proto.ChatMLSErrorCodeEpochStale},
		{chatstate.ErrRekeyRequired, proto.ChatStateErrorCodeRekeyRequired},
		{chatstate.ErrNoGroupState, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrNotHandshake, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrNotApplication, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrHistoryUnavailable, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrDeclarationMismatch, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrGenerationUnknown, proto.ChatMLSErrorCodeFailed},
		{chatstate.ErrBurnForward, proto.ChatMLSErrorCodeFailed},
		{mls.ErrFailed, proto.ChatMLSErrorCodeFailed},
		{mls.ErrNoKeyPackageForWelcome, proto.ChatMLSErrorCodeWelcomeUnusable},
		{mls.ErrGroupMismatch, proto.ChatMLSErrorCodeFailed},
		{mls.ErrUnavailable, proto.ChatMLSErrorCodeCapabilityRequired},
		{chatstate.ErrGroupExists, proto.ChatStateErrorCodeConflict},
		{chatstate.ErrNoPendingCommit, proto.ChatStateErrorCodeConflict},
		{chatstate.ErrCommitMismatch, proto.ChatStateErrorCodeConflict},
		{chatstate.ErrLockTimeout, proto.ChatStateErrorCodeLockTimeout},
		{errors.New("disk full"), proto.ChatStateErrorCodeStorageFailure},
	}
	for _, tc := range cases {
		for _, err := range []error{tc.err, wrapped(tc.err)} {
			resp := chatStateFailure(f.deps, "test", err)
			assertChatStateFailure(t, resp, tc.code)
			if strings.Contains(resp.Error, "while testing") {
				t.Errorf("%v: the error text reached the caller: %q", tc.err, resp.Error)
			}
		}
	}
}
