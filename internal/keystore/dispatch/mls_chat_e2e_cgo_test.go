//go:build mls && cgo

// The MLS chat actions end to end through the dispatcher: each Keeper is its
// own keyring and its own owner partition of the chat state root, every call
// is a Native Messaging request framed as JSON and routed by HandleRequest,
// and the only thing standing in for ariadne is this test deciding which
// Commit won an epoch and handing each Keeper what the server would.

package dispatch

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const (
	e2eOrg    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	e2eConv   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	e2eAlice  = "a1111111-1111-4111-8111-111111111111"
	e2eBob    = "b2222222-2222-4222-8222-222222222222"
	e2eDevice = "d1111111-1111-4111-8111-111111111111"
	e2eNonce  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// keeper is one device: its keyring, its Deps, and the account it signs as.
type keeper struct {
	t       *testing.T
	id      string
	device  string
	store   *keychain.MemorySecretStore
	deps    handlers.Deps
	commits int

	// root, when set, is this Keeper's own chat state root. Two devices of one
	// account would otherwise share an owner partition in the test's root,
	// which two machines never do.
	root string

	// replacing is what the server lists in pending_leaf_replacements of the
	// permits it signs for this Keeper.
	replacing []proto.ChatStateLeafReplacement

	// revoked is what the server lists in pending_device_revocations.
	revoked []proto.MLSDeviceRef
}

func (k *keeper) revoking() []proto.MLSDeviceRef {
	if k.revoked == nil {
		return []proto.MLSDeviceRef{}
	}
	return k.revoked
}

func newKeeper(t *testing.T, id string) *keeper {
	t.Helper()
	store := keychain.NewMemorySecretStore()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(store, pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	k := &keeper{t: t, id: id, device: e2eDevice, store: store, deps: handlers.Deps{
		Logger:            logger.NewMemoryLogger(),
		Store:             store,
		ServerKeyVerifier: verifier.AlwaysOKVerifier{},
	}}
	k.declare(proto.MLSLeafReasonEnroll, time.Now().Unix())
	return k
}

func e2eStateRoot(t *testing.T) {
	t.Helper()
	t.Setenv(chatstate.RootEnvVar, filepath.Join(t.TempDir(), "chat-state"))
}

// call frames one request the way the extension does and routes it.
func (k *keeper) call(action string, payload any) proto.BaseResponse {
	k.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		k.t.Fatal(err)
	}
	msg, err := json.Marshal(proto.BaseRequest{Action: action, RequestID: "r", Payload: body})
	if err != nil {
		k.t.Fatal(err)
	}
	if k.root != "" {
		shared := os.Getenv(chatstate.RootEnvVar)
		os.Setenv(chatstate.RootEnvVar, k.root)
		defer os.Setenv(chatstate.RootEnvVar, shared)
	}
	return HandleRequest(k.deps.Logger, k.deps, msg)
}

func (k *keeper) must(action string, payload any) proto.BaseResponse {
	k.t.Helper()
	resp := k.call(action, payload)
	if !resp.Success {
		k.t.Fatalf("%s as %s: %s (%s)", action, k.id[:8], resp.Error, resp.ErrorCode)
	}
	return resp
}

func (k *keeper) refused(action string, payload any, code string) {
	k.t.Helper()
	resp := k.call(action, payload)
	if resp.Success || string(resp.ErrorCode) != code {
		k.t.Fatalf("%s as %s = %+v; want %s", action, k.id[:8], resp, code)
	}
}

// declare runs mls_leaf_declare then mls_leaf_promote: how a device's leaf key
// becomes the one it signs with, at enrolment and at every rotation.
func (k *keeper) declare(reason string, notBefore int64) proto.MLSLeafDeclaration {
	k.t.Helper()
	resp := k.must(proto.ActionMLSLeafDeclare, proto.MLSLeafDeclareRequest{
		ChallengeToken: "dragpass.mls.leaf.challenge|1|" + k.id + "|" + k.device + "|" + e2eNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSLeafChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       k.id,
		DeviceID:        k.device,
		NotBefore:       notBefore,
		NotAfter:        notBefore + proto.MLSLeafMaxValiditySeconds,
		Reason:          reason,
	})
	d := resp.Data.(proto.MLSLeafDeclareResponseData).MLSLeafDeclaration
	k.must(proto.ActionMLSLeafPromote, proto.MLSLeafPromoteRequest{
		AcceptanceToken: proto.MLSLeafAcceptedToken(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter),
		ServerSignature: "any",
	})
	return d
}

func (k *keeper) keyPackage() proto.MLSMemberKeyPackage {
	k.t.Helper()
	resp := k.must(proto.MLSKeyPackageGenerate, proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: "dragpass.mls.keypackage.challenge|1|" + k.id + "|" + k.device + "|" + e2eNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       k.id,
		DeviceID:        k.device,
		Count:           1,
	})
	kp := resp.Data.(proto.MLSKeyPackageGenerateResponseData).KeyPackages[0]
	return proto.MLSMemberKeyPackage{AccountID: k.id, DeviceID: k.device, KeyPackageB64: kp.KeyPackageB64}
}

// permit is what ariadne would sign for this account. The signature is not
// under test here (the gate tests are in handlers); AlwaysOKVerifier accepts
// it, and everything else about it is what the server would send.
func (k *keeper) permit(removals ...string) proto.ChatStatePermit {
	now := time.Now().Unix()
	if removals == nil {
		removals = []string{}
	}
	replacing := k.replacing
	if replacing == nil {
		replacing = []proto.ChatStateLeafReplacement{}
	}
	return proto.ChatStatePermit{
		AccountID: k.id, OrgID: e2eOrg, ConversationID: e2eConv,
		PendingRemovalAccountIDs: removals,
		PendingLeafReplacements:  replacing,
		PendingDeviceRevocations: k.revoking(),
		IssuedAt:                 now,
		ExpiresAt:                now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion:         1,
		Signature:                base64.StdEncoding.EncodeToString([]byte("signed by the test server")),
	}
}

func (k *keeper) nextCommitID() string {
	k.commits++
	return k.id[:8] + "-7777-4777-8777-" + strconv.FormatInt(int64(700000000000+k.commits), 10)
}

func commitOf(resp proto.BaseResponse) proto.MLSCommitResponseData {
	return resp.Data.(proto.MLSCommitResponseData)
}

func (k *keeper) confirm(id, outcome, winnerB64 string) proto.MLSCommitConfirmResponseData {
	k.t.Helper()
	return k.must(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Outcome: outcome, WinnerCommitB64: winnerB64,
	}).Data.(proto.MLSCommitConfirmResponseData)
}

func (k *keeper) buildUpdate(expected uint64) proto.MLSCommitResponseData {
	k.t.Helper()
	return commitOf(k.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, UpdateSelf: true,
	}))
}

func (k *keeper) processRequest(seq, epoch uint64, commitB64 string) proto.MLSProcessRequest {
	return proto.MLSProcessRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		Seq: seq, Epoch: epoch, CommitB64: commitB64,
	}
}

func (k *keeper) process(seq, epoch uint64, commitB64 string) proto.MLSProcessResponseData {
	k.t.Helper()
	return k.must(proto.MLSProcess, k.processRequest(seq, epoch, commitB64)).Data.(proto.MLSProcessResponseData)
}

// attested is the commit attestation the server would sign for a row whose
// Commit declared these members. AlwaysOKVerifier accepts any signature.
func attested(members ...string) *proto.MLSCommitAttestation {
	sorted := append([]string(nil), members...)
	slices.Sort(sorted)
	return &proto.MLSCommitAttestation{
		MemberAccountIDs: sorted,
		ServerKeyVersion: 1,
		Signature:        base64.StdEncoding.EncodeToString([]byte("signed by the test server")),
	}
}

// processAttested is process with the row's attestation naming members.
func (k *keeper) processAttested(seq, epoch uint64, commitB64 string, members ...string) proto.MLSProcessResponseData {
	k.t.Helper()
	req := k.processRequest(seq, epoch, commitB64)
	req.CommitAttestation = attested(members...)
	return k.must(proto.MLSProcess, req).Data.(proto.MLSProcessResponseData)
}

// dm is Alice and Bob in one conversation, both confirmed at epoch 1: Alice
// creates it with Bob's KeyPackage, the server accepts her Add, and Bob joins
// from the Welcome the accepted row carries.
type dm struct {
	alice, bob *keeper
	seq        uint64
}

func newDM(t *testing.T) *dm {
	t.Helper()
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)

	id := alice.nextCommitID()
	create := proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}
	if got := bob.status(); got.HasGroupState || got.CommitPending || got.NeedsRekey {
		t.Fatalf("bob's status before anything = %+v", got)
	}
	built := commitOf(alice.must(proto.MLSGroupCreate, create))
	alice.assertStatus(alice.status(), 0, id)
	if !built.Created || built.ExpectedEpoch != 0 || built.WelcomeB64 == "" || built.WelcomeReleasable {
		t.Fatalf("group create = %+v", built)
	}
	// A lost response is retried under the same id and answered from the
	// stored pending Commit, not rebuilt.
	again := commitOf(alice.must(proto.MLSGroupCreate, create))
	if again.Created || again.CommitB64 != built.CommitB64 {
		t.Fatal("a retried group create built a second Commit")
	}

	confirmed := alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	if confirmed.Epoch != 1 || !confirmed.WelcomeReleasable {
		t.Fatalf("confirm = %+v", confirmed)
	}
	joined := bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != 1 {
		t.Fatalf("bob joined at epoch %d, want 1", joined.Epoch)
	}
	alice.assertStatus(alice.status(), 1, "")
	bob.assertStatus(bob.status(), 1, "")
	return &dm{alice: alice, bob: bob, seq: 1}
}

func (c *dm) nextSeq() uint64 {
	c.seq++
	return c.seq
}

func TestMLSChatE2E_ADMIsCreatedConfirmedAndJoined(t *testing.T) {
	c := newDM(t)

	// Bob's pins now hold Alice, recorded before the joined state was written.
	if _, err := keychain.GetPeerKeyPin(c.bob.store, c.bob.id, c.alice.id); err != nil {
		t.Fatalf("bob has no pin for alice after joining: %v", err)
	}
	// A second create over the confirmed group is refused and moves nothing.
	c.alice.refused(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{c.bob.keyPackage()},
	}, proto.ChatStateErrorCodeConflict)
}

// A KeyPackage the server hands out for Bob but which names someone else is
// refused before anything is built.
func TestMLSChatE2E_AKeyPackageForAnotherAccountIsRefused(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	kp := bob.keyPackage()
	kp.AccountID = "c3333333-3333-4333-8333-333333333333"
	alice.refused(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{kp},
	}, proto.ChatMLSErrorCodeLeafUntrusted)

	// Nothing was persisted: a correct create afterwards is the first one.
	created := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}))
	if !created.Created {
		t.Fatal("the refused create left a group behind")
	}
}

// Both members build against epoch 1; the server takes Alice's. Alice confirms
// accepted, Bob confirms superseded with Alice's Commit, and both are on
// epoch 2 in the same group: a Commit Bob builds next is one Alice applies.
func TestMLSChatE2E_ACommitRaceConverges(t *testing.T) {
	c := newDM(t)
	aliceCommit := c.alice.buildUpdate(1)
	bobCommit := c.bob.buildUpdate(1)
	c.alice.assertStatus(c.alice.status(), 1, aliceCommit.ClientCommitID)
	c.bob.assertStatus(c.bob.status(), 1, bobCommit.ClientCommitID)

	// Until the verdict arrives neither may build again.
	c.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.bob.nextCommitID(), ExpectedEpoch: 1, UpdateSelf: true,
	}, proto.ChatMLSErrorCodeCommitPending)

	// The response to Bob was lost: unknown moves nothing and hands back the
	// Commit to ask about.
	unknown := c.bob.confirm(bobCommit.ClientCommitID, proto.MLSCommitOutcomeUnknown, "")
	if unknown.CommitB64 != bobCommit.CommitB64 || unknown.Epoch != 1 {
		t.Fatalf("unknown outcome = %+v", unknown)
	}

	won := c.alice.confirm(aliceCommit.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	lost := c.bob.confirm(bobCommit.ClientCommitID, proto.MLSCommitOutcomeSuperseded, aliceCommit.CommitB64)
	if won.Epoch != 2 || lost.Epoch != 2 || lost.WelcomeReleasable || won.WelcomeReleasable {
		t.Fatalf("after the race: alice %+v, bob %+v", won, lost)
	}
	c.alice.assertStatus(c.alice.status(), 2, "")
	c.bob.assertStatus(c.bob.status(), 2, "")
	c.nextSeq()

	next := c.bob.buildUpdate(2)
	c.bob.confirm(next.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := c.alice.process(c.nextSeq(), 3, next.CommitB64); got.Epoch != 3 || got.Removed {
		t.Fatalf("alice applied bob's next commit as %+v", got)
	}
}

// Handshakes apply in epoch order. The same row again, and a row that comes
// after one not yet applied, are both refused and change nothing.
func TestMLSChatE2E_HandshakesApplyInOrder(t *testing.T) {
	c := newDM(t)
	first := c.bob.buildUpdate(1)
	c.bob.confirm(first.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	second := c.bob.buildUpdate(2)
	c.bob.confirm(second.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	c.alice.refused(proto.MLSProcess, c.alice.processRequest(5, 3, second.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	c.alice.process(4, 2, first.CommitB64)
	c.alice.refused(proto.MLSProcess, c.alice.processRequest(4, 2, first.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	// A row that claims the right epoch but carries a Commit for another one
	// passes the ordering check and is refused by MLS, which binds the epoch
	// into the Commit. Nothing is kept.
	c.alice.refused(proto.MLSProcess, c.alice.processRequest(5, 3, first.CommitB64), proto.ChatMLSErrorCodeFailed)
	c.alice.process(5, 3, second.CommitB64)
}

// P3: Bob rotates and promotes a new leaf key. The group still signs as the old
// one until his Update carries the new key, and Alice takes that leaf as an
// entering leaf: full §5.3 checks, and her newest-declaration record for Bob
// moves to the rotated declaration.
func TestMLSChatE2E_ARotatedLeafEntersThroughUpdateSelf(t *testing.T) {
	c := newDM(t)
	before, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}

	c.bob.declare(proto.MLSLeafReasonRotate, before.NotBefore+60)
	update := c.bob.buildUpdate(1)
	c.bob.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 2, update.CommitB64)
	c.alice.assertStatus(c.alice.status(), 2, "")
	c.bob.assertStatus(c.bob.status(), 2, "")

	after, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	if after.NotBefore != before.NotBefore+60 || after.Fingerprint == before.Fingerprint {
		t.Fatalf("alice's record for bob = %+v, was %+v; the rotated leaf did not enter", after, before)
	}

	// The group now signs as the new key on both sides: another Update from
	// Bob needs no new approval and applies.
	next := c.bob.buildUpdate(2)
	c.bob.confirm(next.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 3, next.CommitB64)
}

// ────────────────────────────────────────────────────────────────────────
// Messages.
// ────────────────────────────────────────────────────────────────────────

func (k *keeper) encryptRequest(id string, epoch uint64, text string, removals ...string) proto.MLSEncryptRequest {
	return proto.MLSEncryptRequest{
		Permit: k.permit(removals...), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientMessageID: id, ExpectedEpoch: epoch,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(text)),
	}
}

func (k *keeper) encrypt(id string, epoch uint64, text string) proto.MLSEncryptResponseData {
	k.t.Helper()
	return k.must(proto.MLSEncrypt, k.encryptRequest(id, epoch, text)).Data.(proto.MLSEncryptResponseData)
}

func (k *keeper) decryptRequest(msgs ...proto.MLSDisplayMessage) proto.MLSDecryptBatchForAppDisplayRequest {
	return proto.MLSDecryptBatchForAppDisplayRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, Messages: msgs,
	}
}

func (k *keeper) decrypt(msgs ...proto.MLSDisplayMessage) proto.MLSDisplayResponseData {
	k.t.Helper()
	return k.must(proto.MLSDecryptBatchForAppDisplay, k.decryptRequest(msgs...)).
		Data.(proto.MLSDisplayResponseData)
}

func plaintextOf(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func messageID(n int) string {
	return "eeeeeeee-eeee-4eee-8eee-" + strconv.FormatInt(int64(100000000000+n), 10)
}

// sendTo encrypts on one side and returns the row the server would store.
func (c *dm) send(from *keeper, n int, epoch uint64, text string) proto.MLSDisplayMessage {
	c.alice.t.Helper()
	sent := from.encrypt(messageID(n), epoch, text)
	return proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: sent.CiphertextB64}
}

func assertShown(t *testing.T, got proto.MLSDisplayResponseData, i int,
	text string, sender *keeper, fromHistory bool) {
	t.Helper()
	if len(got.Items) != len(got.PlaintextB64) {
		t.Fatalf("%d items for %d plaintexts", len(got.Items), len(got.PlaintextB64))
	}
	item := got.Items[i]
	if plaintextOf(t, got.PlaintextB64[i]) != text || item.SenderAccountID != sender.id ||
		item.SenderDeviceID != e2eDevice || item.FromHistory != fromHistory ||
		item.ContentType != proto.ChatStateContentTypeApplication {
		t.Fatalf("message %d = %q %+v; want %q from %s (from_history=%v)",
			i, plaintextOf(t, got.PlaintextB64[i]), item, text, sender.id[:8], fromHistory)
	}
}

func TestMLSChatE2E_EachSideEncryptsAndTheOtherReads(t *testing.T) {
	c := newDM(t)
	fromAlice := c.send(c.alice, 1, 1, "hello bob")
	fromBob := c.send(c.bob, 2, 1, "hello alice")

	assertShown(t, c.bob.decrypt(fromAlice), 0, "hello bob", c.alice, false)
	assertShown(t, c.alice.decrypt(fromBob), 0, "hello alice", c.bob, false)

	// The declared position is what the reader verified, and it is this
	// sender's own leaf and generation.
	second := c.alice.encrypt(messageID(3), 1, "again")
	if second.Generation != 1 || second.ContentType != proto.ChatStateContentTypeApplication {
		t.Fatalf("alice's second send declared %+v", second)
	}
	got := c.bob.decrypt(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: second.CiphertextB64})
	if got.Items[0].SenderLeafIndex != second.LeafIndex || got.Items[0].Generation != 1 {
		t.Fatalf("bob read %+v for a send declared as %+v", got.Items[0], second)
	}
	for _, k := range []*keeper{c.alice, c.bob} {
		for _, text := range []string{"hello bob", "hello alice", "again"} {
			if k.deps.Logger.(*logger.MemoryLogger).Contains(text) {
				t.Fatalf("%s's log carries a plaintext", k.id[:8])
			}
		}
	}
}

// A retransmission after a lost response sends the same bytes and takes no
// second position; an epoch the group is not on is refused.
func TestMLSChatE2E_EncryptIsIdempotentAndEpochBound(t *testing.T) {
	c := newDM(t)
	first := c.alice.encrypt(messageID(1), 1, "once")
	again := c.alice.encrypt(messageID(1), 1, "once")
	if !first.Created || again.Created || again.CiphertextB64 != first.CiphertextB64 {
		t.Fatalf("retransmission = %+v, first = %+v", again, first)
	}
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 2, "stale"), proto.ChatMLSErrorCodeEpochStale)

	// The largest plaintext the protocol accepts fits the stored ciphertext.
	big := strings.Repeat("가", proto.MLSEncryptMaxPlaintextBytes/3)
	sent := c.alice.encrypt(messageID(3), 1, big)
	if raw, _ := base64.StdEncoding.DecodeString(sent.CiphertextB64); len(raw) > chatstate.MaxCiphertextBytes {
		t.Fatalf("a %d-byte plaintext made a %d-byte ciphertext", len(big), len(raw))
	}
	assertShown(t, c.bob.decrypt(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: sent.CiphertextB64}),
		0, big, c.alice, false)
}

// A second read of a delivered seq comes from the sealed local copy: the key
// that opened it is gone, and it still names the sender.
func TestMLSChatE2E_AReReadComesFromHistory(t *testing.T) {
	c := newDM(t)
	row := c.send(c.alice, 1, 1, "keep me")
	assertShown(t, c.bob.decrypt(row), 0, "keep me", c.alice, false)
	assertShown(t, c.bob.decrypt(row), 0, "keep me", c.alice, true)
	c.bob.assertStatus(c.bob.status(), 1, "")

	// Still readable after the group has moved on.
	update := c.alice.buildUpdate(1)
	c.alice.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, update.CommitB64)
	assertShown(t, c.bob.decrypt(row), 0, "keep me", c.alice, true)
}

// One message that does not open refuses the page, returns no plaintext and
// writes nothing: the good message is still a first delivery afterwards.
func TestMLSChatE2E_ADisplayBatchIsAllOrNothing(t *testing.T) {
	c := newDM(t)
	good := c.send(c.alice, 1, 1, "fine")
	raw, _ := base64.StdEncoding.DecodeString(c.send(c.alice, 2, 1, "damaged").CiphertextB64)
	raw[len(raw)-1] ^= 1
	bad := proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: base64.StdEncoding.EncodeToString(raw)}

	resp := c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(good, bad))
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeFailed || resp.Data != nil {
		t.Fatalf("a batch with a damaged message = %+v", resp)
	}
	assertShown(t, c.bob.decrypt(good), 0, "fine", c.alice, false)

	// A handshake does not belong on this path.
	update := c.alice.buildUpdate(1)
	c.bob.refused(proto.MLSDecryptBatchForAppDisplay,
		c.bob.decryptRequest(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: update.CommitB64}),
		proto.ChatStateErrorCodeInvalidInput)
}

// S-1: once a permit names Bob as removed from the organization, Alice may not
// encrypt while her confirmed group holds his leaf — not even under a later
// permit that stops naming him. Her own confirmed Remove lifts it.
func TestMLSChatE2E_TheRemovalLatchHoldsUntilARemoveIsConfirmed(t *testing.T) {
	c := newDM(t)
	// Status shows the latch before anything is tried.
	c.alice.assertStatus(c.alice.status(c.bob.id), 1, "", c.bob.id)
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "to bob", c.bob.id),
		proto.ChatMLSErrorCodeRotationPending)
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "to bob"),
		proto.ChatMLSErrorCodeRotationPending)

	remove := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(c.bob.id), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, RemoveAccountIDs: []string{c.bob.id},
		OrgRemovalStatements: []proto.MLSOrgRemovalStatement{orgRemoval(newKeeper(t, e2eAdmin), c.bob.id)},
	}))
	// Pending is not confirmed: still latched, and now also waiting.
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "to bob"),
		proto.ChatMLSErrorCodeCommitPending)
	c.alice.assertStatus(c.alice.status(c.bob.id), 1, remove.ClientCommitID, c.bob.id)
	c.alice.confirm(remove.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.assertStatus(c.alice.status(c.bob.id), 2, "")

	sent := c.alice.must(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 2, "bob is gone", c.bob.id)).
		Data.(proto.MLSEncryptResponseData)
	// The refusals consumed no position: the first message of epoch 2 is
	// generation 0.
	if sent.Epoch != 2 || sent.Generation != 0 {
		t.Fatalf("after the remove alice sent %+v", sent)
	}
	// Bob learns he was removed, from the admin's statement the Commit
	// carries.
	if got := c.bob.processAttested(c.nextSeq(), 2, remove.CommitB64, c.alice.id); !got.Removed || !slices.Equal(got.RemovedAccountIDs, []string{c.bob.id}) {
		t.Fatalf("bob processed his removal as %+v", got)
	}
}

// After the race the two sides are one group: messages cross both ways.
func TestMLSChatE2E_MessagesCrossAfterARaceAndARotation(t *testing.T) {
	c := newDM(t)
	a, b := c.alice.buildUpdate(1), c.bob.buildUpdate(1)
	c.alice.confirm(a.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.confirm(b.ClientCommitID, proto.MLSCommitOutcomeSuperseded, a.CommitB64)
	c.nextSeq()
	assertShown(t, c.alice.decrypt(c.send(c.bob, 1, 2, "after the race")), 0, "after the race", c.bob, false)

	before, _, _ := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	c.bob.declare(proto.MLSLeafReasonRotate, before.NotBefore+60)
	update := c.bob.buildUpdate(2)
	c.bob.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 3, update.CommitB64)
	assertShown(t, c.alice.decrypt(c.send(c.bob, 2, 3, "new key")), 0, "new key", c.bob, false)
	assertShown(t, c.bob.decrypt(c.send(c.alice, 3, 3, "got it")), 0, "got it", c.alice, false)
}

// ────────────────────────────────────────────────────────────────────────
// Status.
// ────────────────────────────────────────────────────────────────────────

func (k *keeper) statusWith(p proto.ChatStatePermit) proto.MLSConversationStatusResponseData {
	k.t.Helper()
	return k.must(proto.MLSConversationStatus, proto.MLSConversationStatusRequest{
		Permit: p, OrgID: e2eOrg, ConversationID: e2eConv,
	}).Data.(proto.MLSConversationStatusResponseData)
}

func (k *keeper) status(removals ...string) proto.MLSConversationStatusResponseData {
	k.t.Helper()
	return k.statusWith(k.permit(removals...))
}

func (k *keeper) assertStatus(got proto.MLSConversationStatusResponseData, epoch uint64, pendingID string, latch ...string) {
	k.t.Helper()
	if latch == nil {
		latch = []string{}
	}
	if got.NeedsRekey || !got.HasGroupState || got.Epoch != epoch || got.CommitPending != (pendingID != "") ||
		got.PendingClientCommitID != pendingID || strings.Join(got.RemovalLatch, ",") != strings.Join(latch, ",") ||
		got.RemovalLatch == nil {
		k.t.Fatalf("%s status = %+v; want epoch %d, pending %q, latch %v", k.id[:8], got, epoch, pendingID, latch)
	}
}

// A rewind — here, a server that has accepted a send this record does not
// know about — latches the conversation. Status says so before a send is
// tried, and every operation on it is refused with CHAT_STATE_REKEY_REQUIRED.
func TestMLSChatE2E_StatusReportsARewindLatch(t *testing.T) {
	c := newDM(t)
	ahead := c.alice.permit()
	ahead.WatermarkEpoch, ahead.WatermarkNextApplication = 9, 1
	if got := c.alice.statusWith(ahead); !got.NeedsRekey || got.HasGroupState || got.RemovalLatch == nil {
		t.Fatalf("status of a rewound record = %+v", got)
	}
	if got := c.alice.status(); !got.NeedsRekey {
		t.Fatalf("the latch did not hold for the next permit: %+v", got)
	}
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "x"), proto.ChatStateErrorCodeRekeyRequired)
	c.alice.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, UpdateSelf: true,
	}, proto.ChatStateErrorCodeRekeyRequired)
	// Bob's copy is his own and is not affected.
	c.bob.assertStatus(c.bob.status(), 1, "")
}

// ────────────────────────────────────────────────────────────────────────
// Leaf rotation and the KeyPackage pool.
// ────────────────────────────────────────────────────────────────────────

func (k *keeper) poolSize() int {
	k.t.Helper()
	store, err := chatstate.Open(k.store, k.id)
	if err != nil {
		k.t.Fatal(err)
	}
	defer store.Close()
	n, err := store.KeyPackagePoolSize(time.Now())
	if err != nil {
		k.t.Fatal(err)
	}
	return n
}

// Bob's KeyPackage is handed to Alice, and Bob rotates before her Welcome
// arrives. The promote dropped the old leaf's pool entry, so the Welcome
// cannot be joined: a distinct code that says to be invited again, and
// nothing written.
func TestMLSChatE2E_AWelcomeForAKeyPackageOfTheOldLeafIsUnusable(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	kp := bob.keyPackage()
	id := alice.nextCommitID()
	built := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{kp},
	}))
	alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")

	bob.declare(proto.MLSLeafReasonRotate, time.Now().Unix()+60)
	if n := bob.poolSize(); n != 0 {
		t.Fatalf("bob's pool holds %d entries of the old leaf after the promote", n)
	}
	join := proto.MLSJoinRequest{Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64}
	bob.refused(proto.MLSJoin, join, proto.ChatMLSErrorCodeWelcomeUnusable)
	if got := bob.status(); got.HasGroupState || got.CommitPending || got.NeedsRekey || got.Epoch != 0 {
		t.Fatalf("bob's status after the refused join = %+v", got)
	}
	if _, err := keychain.GetPeerKeyPin(bob.store, bob.id, alice.id); err == nil {
		t.Fatal("the refused join recorded a pin")
	}

	// A KeyPackage of the new leaf is kept.
	bob.keyPackage()
	if n := bob.poolSize(); n != 1 {
		t.Fatalf("bob's pool holds %d after a new generation, want 1", n)
	}
}

// ────────────────────────────────────────────────────────────────────────
// A conversation latched NeedsRekey is read-only on this device.
// ────────────────────────────────────────────────────────────────────────

// Alice read one message from Bob before her record was found rewound. That
// message stays readable from her history; everything that touches MLS is
// refused with CHAT_STATE_REKEY_REQUIRED, and so is a page that mixes the two.
func TestMLSChatE2E_ALatchedConversationKeepsItsHistoryReadable(t *testing.T) {
	c := newDM(t)
	read := c.send(c.bob, 1, 1, "before the rewind")
	assertShown(t, c.alice.decrypt(read), 0, "before the rewind", c.bob, false)
	unread := c.send(c.bob, 2, 1, "after the rewind")

	ahead := c.alice.permit()
	ahead.WatermarkEpoch, ahead.WatermarkNextApplication = 9, 1
	if got := c.alice.statusWith(ahead); !got.NeedsRekey {
		t.Fatalf("status of a rewound record = %+v", got)
	}

	assertShown(t, c.alice.decrypt(read), 0, "before the rewind", c.bob, true)
	c.alice.refused(proto.MLSDecryptBatchForAppDisplay, c.alice.decryptRequest(unread), proto.ChatStateErrorCodeRekeyRequired)
	resp := c.alice.call(proto.MLSDecryptBatchForAppDisplay, c.alice.decryptRequest(read, unread))
	if resp.Success || string(resp.ErrorCode) != proto.ChatStateErrorCodeRekeyRequired || resp.Data != nil {
		t.Fatalf("a mixed batch under the latch = %+v", resp)
	}
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(3), 1, "x"), proto.ChatStateErrorCodeRekeyRequired)
	c.alice.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, UpdateSelf: true,
	}, proto.ChatStateErrorCodeRekeyRequired)
	update := c.bob.buildUpdate(1)
	c.bob.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.refused(proto.MLSProcess, c.alice.processRequest(c.nextSeq(), 2, update.CommitB64),
		proto.ChatStateErrorCodeRekeyRequired)

	// A Welcome to one of Alice's KeyPackages, for the latched conversation:
	// the join is refused on the latch and the pool entry is kept.
	carol := newKeeper(t, "c3333333-3333-4333-8333-333333333333")
	id := carol.nextCommitID()
	invite := commitOf(carol.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{c.alice.keyPackage()},
	}))
	carol.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	c.alice.refused(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: invite.WelcomeB64,
	}, proto.ChatStateErrorCodeRekeyRequired)
	if n := c.alice.poolSize(); n != 1 {
		t.Fatalf("alice's pool holds %d after the refused join, want the entry kept", n)
	}

	// The refusals changed nothing: the history is still there and the
	// latch still holds.
	assertShown(t, c.alice.decrypt(read), 0, "before the rewind", c.bob, true)
	if got := c.alice.status(); !got.NeedsRekey {
		t.Fatalf("the latch did not hold: %+v", got)
	}
}

// Q11: KeyPackages this Keeper builds advertise the roles extension, so the
// sweep keeps them all; it is idempotent. The drop of entries an older Keeper
// built is TestMLSAdversary_ThePoolSweepDropsAnOldKeepersKeyPackage.
func TestMLSChatE2E_ThePoolSweepKeepsThisKeepersKeyPackages(t *testing.T) {
	e2eStateRoot(t)
	bob := newKeeper(t, e2eBob)
	bob.keyPackage()
	bob.keyPackage()
	for range 2 {
		got := bob.must(proto.MLSKeyPackagePoolSweep, proto.MLSKeyPackagePoolSweepRequest{AccountID: bob.id}).
			Data.(proto.MLSKeyPackagePoolSweepResponseData)
		if got.Dropped != 0 || got.Remaining != 2 {
			t.Fatalf("sweep = %+v; want nothing dropped and 2 remaining", got)
		}
	}
	if n := bob.poolSize(); n != 2 {
		t.Fatalf("pool size after the sweep = %d", n)
	}
}
