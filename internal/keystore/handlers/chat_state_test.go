// chat_state_test.go — the conversation-state actions at the protocol edge.
//
// The storage guarantees themselves (serialization, atomic replacement,
// rollback refusal, SIGKILL) belong to internal/keystore/chatstate and are
// tested there, twice: in process and across two real processes. What is left
// for this file is the gate, and one assertion in it carries more weight than
// the rest — an unauthorized call must leave the state directory *absent*, not
// merely fail. A failure code proves the answer was refused; an untouched
// directory proves nothing was opened to produce it.
//
// The harness (msgTestServerKey, msgTestVerifier, msgTestClock, newTestDeps,
// chatMarshal) and the UUID constants are shared with the chat reveal tests in
// the same package.

package handlers

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const chatStateClientMsgID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

var (
	chatStateIVB64      = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, proto.ConversationIVBytes))
	chatStateCtB64      = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	chatStateOtherCtB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 40))
)

// ────────────────────────────────────────────────────────────────────────
// Harness
// ────────────────────────────────────────────────────────────────────────

type chatStateFixture struct {
	deps  Deps
	log   *logger.MemoryLogger
	clock *msgTestClock
	key   *rsa.PrivateKey
	root  string
}

// newChatStateFixture points the state root at a directory that does not exist
// yet. Its absence is what the unauthorized cases assert against, so the root
// is deliberately a subdirectory of the temp dir rather than the temp dir
// itself, which the testing package has already created.
func newChatStateFixture(t *testing.T) *chatStateFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "chat-state")
	t.Setenv(chatstate.RootEnvVar, root)
	deps, log, _ := newTestDeps(t)
	clock := &msgTestClock{unix: chatNowUnix}
	deps.Clock = clock.now
	key := msgTestServerKey()
	deps.ServerKeyVerifier = msgTestVerifier{version: msgServerKeyVersion, public: &key.PublicKey}
	return &chatStateFixture{deps: deps, log: log, clock: clock, key: key, root: root}
}

func (f *chatStateFixture) unsignedPermit() proto.ChatStatePermit {
	now := f.clock.now().Unix()
	return proto.ChatStatePermit{
		AccountID:        chatAccountID,
		OrgID:            chatOrgID,
		ConversationID:   chatConvID,
		IssuedAt:         now,
		ExpiresAt:        now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion: msgServerKeyVersion,
	}
}

func (f *chatStateFixture) sign(t *testing.T, p proto.ChatStatePermit) proto.ChatStatePermit {
	t.Helper()
	sig, err := crypto.SignData(f.key, proto.ChatStatePermitCanonical(p))
	if err != nil {
		t.Fatalf("sign permit: %v", err)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}

func (f *chatStateFixture) permit(t *testing.T) proto.ChatStatePermit {
	t.Helper()
	return f.sign(t, f.unsignedPermit())
}

func (f *chatStateFixture) reserveRequest(p proto.ChatStatePermit, count int) proto.ChatStateReserveSendRequest {
	return proto.ChatStateReserveSendRequest{
		Permit:         p,
		OrgID:          p.OrgID,
		ConversationID: p.ConversationID,
		Count:          count,
	}
}

func (f *chatStateFixture) commitRequest(
	p proto.ChatStatePermit, index uint64, clientMessageID, ciphertextB64 string,
) proto.ChatStateCommitOutboxRequest {
	return proto.ChatStateCommitOutboxRequest{
		Permit:          p,
		OrgID:           p.OrgID,
		ConversationID:  p.ConversationID,
		ClientMessageID: clientMessageID,
		Epoch:           0,
		ChainIndex:      index,
		IVB64:           chatStateIVB64,
		CiphertextB64:   ciphertextB64,
	}
}

func (f *chatStateFixture) reserve(t *testing.T, req proto.ChatStateReserveSendRequest) proto.BaseResponse {
	t.Helper()
	return HandleChatStateReserveSend(f.deps, chatMarshal(t, req))
}

func (f *chatStateFixture) commit(t *testing.T, req proto.ChatStateCommitOutboxRequest) proto.BaseResponse {
	t.Helper()
	return HandleChatStateCommitOutbox(f.deps, chatMarshal(t, req))
}

func (f *chatStateFixture) readOutbox(t *testing.T, p proto.ChatStatePermit, clientMessageID string) proto.BaseResponse {
	t.Helper()
	return HandleChatStateReadOutbox(f.deps, chatMarshal(t, proto.ChatStateReadOutboxRequest{
		Permit:          p,
		OrgID:           p.OrgID,
		ConversationID:  p.ConversationID,
		ClientMessageID: clientMessageID,
	}))
}

func (f *chatStateFixture) markReceivedRequest(
	p proto.ChatStatePermit, leafIndex uint32, contentType string, generation uint64,
) proto.ChatStateMarkReceivedRequest {
	return proto.ChatStateMarkReceivedRequest{
		Permit:          p,
		OrgID:           p.OrgID,
		ConversationID:  p.ConversationID,
		Epoch:           0,
		SenderLeafIndex: leafIndex,
		ContentType:     contentType,
		Generation:      generation,
	}
}

func (f *chatStateFixture) markReceived(t *testing.T, req proto.ChatStateMarkReceivedRequest) proto.BaseResponse {
	t.Helper()
	return HandleChatStateMarkReceived(f.deps, chatMarshal(t, req))
}

func (f *chatStateFixture) purge(t *testing.T, ownerAccountID string) proto.BaseResponse {
	t.Helper()
	return HandleChatStatePurge(f.deps, chatMarshal(t, proto.ChatStatePurgeRequest{
		OwnerAccountID: ownerAccountID,
	}))
}

// assertStateRootAbsent is the assertion the whole permit gate exists to make
// true: not "the call failed" but "the call never reached the filesystem".
func (f *chatStateFixture) assertStateRootAbsent(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(f.root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("state root %s exists after an unauthorized call (stat err %v)", f.root, err)
	}
}

func assertChatStateFailure(t *testing.T, resp proto.BaseResponse, wantCode string) {
	t.Helper()
	if resp.Success {
		t.Fatalf("expected failure %s, got success with %+v", wantCode, resp.Data)
	}
	if resp.ErrorCode != wantCode {
		t.Fatalf("error_code = %q, want %q (message %q)", resp.ErrorCode, wantCode, resp.Error)
	}
	if resp.Data != nil {
		t.Fatalf("failure must carry no data, got %+v", resp.Data)
	}
}

func reservationData(t *testing.T, resp proto.BaseResponse) proto.ChatStateReserveSendResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("reserve failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.ChatStateReserveSendResponseData)
	if !ok {
		t.Fatalf("reserve data type = %T", resp.Data)
	}
	return data
}

func commitData(t *testing.T, resp proto.BaseResponse) proto.ChatStateCommitOutboxResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("commit failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.ChatStateCommitOutboxResponseData)
	if !ok {
		t.Fatalf("commit data type = %T", resp.Data)
	}
	return data
}

// ────────────────────────────────────────────────────────────────────────
// The permit gate: nothing is opened before it passes
// ────────────────────────────────────────────────────────────────────────

func TestChatState_UnauthorizedCallsNeverOpenTheStateDirectory(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReserveSendRequest
		code   string
	}{
		{
			name: "unsigned permit",
			mutate: func(_ *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				p := f.unsignedPermit()
				p.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
				return f.reserveRequest(p, 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "watermark changed after signing",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				p.WatermarkNextApplication += 9
				return f.reserveRequest(p, 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "server key version not pinned",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				p := f.unsignedPermit()
				p.ServerKeyVersion = msgServerKeyVersion + 1
				return f.reserveRequest(f.sign(t, p), 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "request names a different conversation than the permit",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				req := f.reserveRequest(p, 1)
				req.ConversationID = chatOtherUUID
				return req
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit has expired",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				f.clock.advance(proto.ChatStatePermitTTLSeconds)
				return f.reserveRequest(p, 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit window is wider than the fixed span",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				p := f.unsignedPermit()
				p.ExpiresAt = p.IssuedAt + 2*proto.ChatStatePermitTTLSeconds
				return f.reserveRequest(f.sign(t, p), 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit is issued too far in the future",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				p := f.unsignedPermit()
				p.IssuedAt += 60
				p.ExpiresAt = p.IssuedAt + proto.ChatStatePermitTTLSeconds
				return f.reserveRequest(f.sign(t, p), 1)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "count is above the cap",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReserveSendRequest {
				return f.reserveRequest(p, proto.ChatStateMaxReserveCount+1)
			},
			code: proto.ChatStateErrorCodeInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatStateFixture(t)
			req := tc.mutate(t, f, f.permit(t))
			assertChatStateFailure(t, f.reserve(t, req), tc.code)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestChatState_MalformedRequestsNeverOpenTheStateDirectory(t *testing.T) {
	f := newChatStateFixture(t)
	base := chatMarshal(t, f.reserveRequest(f.permit(t), 1))

	var object map[string]json.RawMessage
	if err := json.Unmarshal(base, &object); err != nil {
		t.Fatalf("unmarshal base request: %v", err)
	}

	withExtra := cloneJSONObject(object)
	withExtra["unexpected"] = json.RawMessage(`1`)

	missingCount := cloneJSONObject(object)
	delete(missingCount, "count")

	cases := []struct {
		name    string
		payload json.RawMessage
	}{
		{"unknown field", chatMarshal(t, withExtra)},
		{"missing field", chatMarshal(t, missingCount)},
		{
			// A duplicate key cannot be produced by marshalling a map, and it
			// is the case that matters most here: json.Unmarshal would keep the
			// last value, so the signature would cover one conversation and the
			// chain would advance in another.
			"duplicate conversation_id",
			json.RawMessage(`{"permit":{},"org_id":"` + chatOrgID +
				`","conversation_id":"` + chatConvID +
				`","conversation_id":"` + chatOtherUUID + `","count":1}`),
		},
		{"over the size cap", json.RawMessage(`{"pad":"` + strings.Repeat("a", proto.ChatStateMaxRequestBytes) + `"}`)},
		{"empty payload", json.RawMessage(``)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleChatStateReserveSend(f.deps, tc.payload)
			assertChatStateFailure(t, resp, proto.ChatStateErrorCodeInvalidInput)
			f.assertStateRootAbsent(t)
		})
	}
}

func cloneJSONObject(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestChatState_EveryPermitGatedActionRefusesAnUnsignedPermit covers the three
// actions the table above exercises only through reserve. Registering an action
// without wiring it into openChatState would otherwise pass unnoticed.
func TestChatState_EveryPermitGatedActionRefusesAnUnsignedPermit(t *testing.T) {
	f := newChatStateFixture(t)
	unsigned := f.unsignedPermit()
	unsigned.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))

	responses := map[string]proto.BaseResponse{
		proto.ChatStateReserveSend:  f.reserve(t, f.reserveRequest(unsigned, 1)),
		proto.ChatStateCommitOutbox: f.commit(t, f.commitRequest(unsigned, 0, chatStateClientMsgID, chatStateCtB64)),
		proto.ChatStateReadOutbox:   f.readOutbox(t, unsigned, chatStateClientMsgID),
		proto.ChatStateMarkReceived: f.markReceived(t,
			f.markReceivedRequest(unsigned, 0, proto.ChatStateContentTypeApplication, 0)),
	}
	for action, resp := range responses {
		if resp.ErrorCode != proto.ChatStateErrorCodeNotAuthorized {
			t.Errorf("%s: error_code = %q, want %q", action, resp.ErrorCode, proto.ChatStateErrorCodeNotAuthorized)
		}
	}
	f.assertStateRootAbsent(t)
}

// ────────────────────────────────────────────────────────────────────────
// The authorized flow
// ────────────────────────────────────────────────────────────────────────

func TestChatState_ReserveThenCommitThenRead(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)

	first := reservationData(t, f.reserve(t, f.reserveRequest(permit, 2)))
	if first.FirstChainIndex != 0 || first.Count != 2 {
		t.Fatalf("first reservation = %+v", first)
	}
	second := reservationData(t, f.reserve(t, f.reserveRequest(permit, 1)))
	if second.FirstChainIndex != 2 {
		t.Fatalf("second reservation started at %d, want 2", second.FirstChainIndex)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("generation did not advance: %d then %d", first.Generation, second.Generation)
	}

	stored := commitData(t, f.commit(t, f.commitRequest(permit, 0, chatStateClientMsgID, chatStateCtB64)))
	if !stored.Stored {
		t.Fatal("first commit reported stored = false")
	}

	read := f.readOutbox(t, permit, chatStateClientMsgID)
	if !read.Success {
		t.Fatalf("read outbox failed: %s (%s)", read.Error, read.ErrorCode)
	}
	entry, ok := read.Data.(proto.ChatStateReadOutboxResponseData)
	if !ok {
		t.Fatalf("read outbox data type = %T", read.Data)
	}
	if entry.CiphertextB64 != chatStateCtB64 || entry.IVB64 != chatStateIVB64 || entry.ChainIndex != 0 {
		t.Fatalf("read outbox returned %+v", entry)
	}
}

// TestChatState_RetransmitReturnsTheStoredBytes is the action-level half of
// ADR S7: a second send of the same client message id is a retransmission of
// the same ciphertext, never a second encryption at a second position.
func TestChatState_RetransmitReturnsTheStoredBytes(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 2)))

	first := commitData(t, f.commit(t, f.commitRequest(permit, 0, chatStateClientMsgID, chatStateCtB64)))
	if !first.Stored {
		t.Fatal("first commit reported stored = false")
	}

	// Same client message id, different ciphertext at a different reserved
	// position: what comes back has to be the first one.
	retry := commitData(t, f.commit(t, f.commitRequest(permit, 1, chatStateClientMsgID, chatStateOtherCtB64)))
	if retry.Stored {
		t.Fatal("a retransmission reported stored = true")
	}
	if retry.CiphertextB64 != chatStateCtB64 || retry.ChainIndex != 0 {
		t.Fatalf("retransmission returned %+v, want the original bytes at index 0", retry)
	}
}

func TestChatState_CommitRefusesAnUnreservedPosition(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 1)))

	resp := f.commit(t, f.commitRequest(permit, 5, chatStateClientMsgID, chatStateCtB64))
	assertChatStateFailure(t, resp, proto.ChatStateErrorCodeConflict)
}

func TestChatState_CommitRefusesAPositionAlreadyCarryingAMessage(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 2)))
	commitData(t, f.commit(t, f.commitRequest(permit, 0, chatStateClientMsgID, chatStateCtB64)))

	resp := f.commit(t, f.commitRequest(permit, 0, chatOtherUUID, chatStateOtherCtB64))
	assertChatStateFailure(t, resp, proto.ChatStateErrorCodeConflict)
}

func TestChatState_ReadOutboxReportsAMissingEntry(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 1)))

	assertChatStateFailure(t, f.readOutbox(t, permit, chatStateClientMsgID), proto.ChatStateErrorCodeNotFound)
}

func TestChatState_MarkReceivedIsIdempotent(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	req := f.markReceivedRequest(permit, 1, proto.ChatStateContentTypeApplication, 4)

	first := f.markReceived(t, req)
	if !first.Success {
		t.Fatalf("first mark failed: %s (%s)", first.Error, first.ErrorCode)
	}
	firstData, ok := first.Data.(proto.ChatStateMarkReceivedResponseData)
	if !ok || !firstData.FirstDelivery {
		t.Fatalf("first mark data = %+v", first.Data)
	}

	second := f.markReceived(t, req)
	secondData, ok := second.Data.(proto.ChatStateMarkReceivedResponseData)
	if !ok || secondData.FirstDelivery {
		t.Fatalf("redelivery reported first_delivery = %+v", second.Data)
	}
	if secondData.Generation != firstData.Generation {
		t.Fatalf("redelivery advanced the generation: %d then %d",
			firstData.Generation, secondData.Generation)
	}
}

// The delivery of two members' first message of one epoch, which the two-slot
// position judged a redelivery and dropped.
func TestChatState_MarkReceivedDistinguishesSenders(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)

	fromOne := f.markReceived(t, f.markReceivedRequest(permit, 1, proto.ChatStateContentTypeApplication, 0))
	if !fromOne.Success {
		t.Fatalf("leaf 1 failed: %s (%s)", fromOne.Error, fromOne.ErrorCode)
	}
	fromTwo := f.markReceived(t, f.markReceivedRequest(permit, 2, proto.ChatStateContentTypeApplication, 0))
	if !fromTwo.Success {
		t.Fatalf("leaf 2 failed: %s (%s)", fromTwo.Error, fromTwo.ErrorCode)
	}
	for name, resp := range map[string]proto.BaseResponse{"leaf 1": fromOne, "leaf 2": fromTwo} {
		data, ok := resp.Data.(proto.ChatStateMarkReceivedResponseData)
		if !ok || !data.FirstDelivery {
			t.Fatalf("%s generation 0 was not a first delivery: %+v", name, resp.Data)
		}
	}
}

func TestChatState_MarkReceivedRefusesAnUnknownContentType(t *testing.T) {
	f := newChatStateFixture(t)
	req := f.markReceivedRequest(f.permit(t), 1, "commit", 0)
	assertChatStateFailure(t, f.markReceived(t, req), proto.ChatStateErrorCodeInvalidInput)
	f.assertStateRootAbsent(t)
}

// The two-slot request shape is refused, not defaulted. The strict decoder sees
// an unknown `chain_index` and three missing keys, and a position that defaulted
// its leaf and its ratchet would deduplicate against a chain nobody sent on.
func TestChatState_MarkReceivedRefusesTheTwoSlotRequestShape(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	payload, err := json.Marshal(map[string]any{
		"permit":          permit,
		"org_id":          permit.OrgID,
		"conversation_id": permit.ConversationID,
		"epoch":           0,
		"chain_index":     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertChatStateFailure(t,
		HandleChatStateMarkReceived(f.deps, payload), proto.ChatStateErrorCodeInvalidInput)
	f.assertStateRootAbsent(t)
}

// TestChatState_OwnerComesFromThePermit checks the partitioning the handler
// relies on: two accounts on one device share a state root and must not share a
// chain. The request never names an owner, so the only way this can go wrong is
// the handler reading it from somewhere other than the permit.
func TestChatState_OwnerComesFromThePermit(t *testing.T) {
	f := newChatStateFixture(t)

	mine := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(mine, 3)))

	otherUnsigned := f.unsignedPermit()
	otherUnsigned.AccountID = chatOtherUUID
	other := f.sign(t, otherUnsigned)

	got := reservationData(t, f.reserve(t, f.reserveRequest(other, 1)))
	if got.FirstChainIndex != 0 {
		t.Fatalf("the second account started at index %d, want 0 — the chains are shared",
			got.FirstChainIndex)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Rollback and erasure at the protocol edge
// ────────────────────────────────────────────────────────────────────────

// TestChatState_ADeletedStateFileIsRefusedAsARewind removes the sealed file
// while the keyring anchor still remembers the positions it authorized. That is
// the shape of a restore: the anchor is the surviving witness, and the action
// has to close with the code that means "establish a new epoch" rather than
// quietly hand out index 0 a second time.
func TestChatState_ADeletedStateFileIsRefusedAsARewind(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 4)))

	removeSealedRecords(t, f.root)

	assertChatStateFailure(t, f.reserve(t, f.reserveRequest(permit, 1)), proto.ChatStateErrorCodeRekeyRequired)
	// The refusal latches: a retry is not a way out.
	assertChatStateFailure(t, f.reserve(t, f.reserveRequest(permit, 1)), proto.ChatStateErrorCodeRekeyRequired)
}

func removeSealedRecords(t *testing.T, root string) {
	t.Helper()
	removed := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".state") {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		removed++
		return nil
	})
	if err != nil {
		t.Fatalf("walk state root: %v", err)
	}
	if removed == 0 {
		t.Fatal("no sealed record was found to remove — the fixture never wrote one")
	}
}

func TestChatState_PurgeRemovesTheStateAndNeedsNoPermit(t *testing.T) {
	f := newChatStateFixture(t)
	permit := f.permit(t)
	reservationData(t, f.reserve(t, f.reserveRequest(permit, 1)))

	resp := f.purge(t, chatAccountID)
	if !resp.Success {
		t.Fatalf("purge failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.ChatStatePurgeResponseData)
	if !ok || data.RemovedConversations != 1 {
		t.Fatalf("purge data = %+v, want one removed conversation", resp.Data)
	}

	// After a purge the conversation is a first use again, not a rewind: the
	// seal key went with the files, so there is no old state left to be behind.
	fresh := reservationData(t, f.reserve(t, f.reserveRequest(f.permit(t), 1)))
	if fresh.FirstChainIndex != 0 {
		t.Fatalf("after a purge the chain resumed at %d, want 0", fresh.FirstChainIndex)
	}
}

func TestChatState_PurgeRejectsAMalformedOwner(t *testing.T) {
	f := newChatStateFixture(t)
	assertChatStateFailure(t, f.purge(t, "not-a-uuid"), proto.ChatStateErrorCodeInvalidInput)
}

// TestChatStateReserveCapMatchesTheStore keeps the wire cap and the storage cap
// from drifting apart. A wire cap above the store's would turn a request the
// protocol advertises as valid into a storage failure.
func TestChatStateReserveCapMatchesTheStore(t *testing.T) {
	if proto.ChatStateMaxReserveCount != chatstate.MaxReserveCount {
		t.Fatalf("proto cap %d != store cap %d",
			proto.ChatStateMaxReserveCount, chatstate.MaxReserveCount)
	}
}

// The wire spells the two ratchets and the store stores them, so a drift here
// would pass validation and then be refused as a storage failure.
func TestChatStateContentTypesMatchTheStore(t *testing.T) {
	if proto.ChatStateContentTypeHandshake != string(chatstate.ContentTypeHandshake) {
		t.Fatalf("proto %q != store %q",
			proto.ChatStateContentTypeHandshake, chatstate.ContentTypeHandshake)
	}
	if proto.ChatStateContentTypeApplication != string(chatstate.ContentTypeApplication) {
		t.Fatalf("proto %q != store %q",
			proto.ChatStateContentTypeApplication, chatstate.ContentTypeApplication)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The watermark's leaf slot: whose chain the server is describing
// ────────────────────────────────────────────────────────────────────────

// seedSendPositionAtLeaf puts one outbox entry in the record under a position
// that names its ratchet and its leaf, which is what the MLS send path writes
// and what teaches the record whose leaf it is on.
func seedSendPositionAtLeaf(t *testing.T, f *chatStateFixture, leaf uint32) {
	t.Helper()
	store, err := chatstate.Open(f.deps.Store, chatAccountID)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	reservation, err := store.Reserve(chatConvID, 1, chatstate.ServerWatermark{})
	if err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, _, err := store.CommitOutbox(chatConvID, chatstate.ServerWatermark{}, chatstate.OutboxEntry{
		ClientMessageID: chatStateClientMsgID,
		Position: chatstate.Position{
			SenderLeafIndex: leaf,
			ContentType:     chatstate.ContentTypeApplication,
			Generation:      reservation.FirstChainIndex,
		},
		IV:         bytes.Repeat([]byte{7}, proto.ConversationIVBytes),
		Ciphertext: bytes.Repeat([]byte{9}, 32),
	}); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}
}

// watermarkPermit signs a permit carrying one accepted application position on
// the named leaf. The epoch stays behind the record's so the rollback axes have
// nothing to say and the leaf slot is the only thing under test.
func (f *chatStateFixture) watermarkPermit(t *testing.T, leaf uint32, nextApplication uint64) proto.ChatStatePermit {
	t.Helper()
	p := f.unsignedPermit()
	p.WatermarkLeafIndex = leaf
	p.WatermarkNextApplication = nextApplication
	return f.sign(t, p)
}

// A permit describing another leaf's chain is refused rather than used to judge
// this one's. It is an authorization failure and not a rewind, so the next
// permit naming the right leaf still works — nothing was latched.
func TestChatState_AWatermarkNamingAnotherLeafIsRefused(t *testing.T) {
	f := newChatStateFixture(t)
	seedSendPositionAtLeaf(t, f, 3)

	wrong := f.reserveRequest(f.watermarkPermit(t, 9, 1), 1)
	assertChatStateFailure(t, f.reserve(t, wrong), proto.ChatStateErrorCodeNotAuthorized)

	right := f.reserveRequest(f.watermarkPermit(t, 3, 1), 1)
	if resp := f.reserve(t, right); !resp.Success {
		t.Fatalf("a watermark on this device's own leaf was refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
}

// Until the server has accepted a position there is no chain for the leaf slot
// to name, so it carries nothing and is ignored — including on the first send,
// where this device's leaf is non-zero and the watermark is all zeros.
func TestChatState_AnEmptyWatermarkIgnoresItsLeafSlot(t *testing.T) {
	f := newChatStateFixture(t)
	seedSendPositionAtLeaf(t, f, 3)

	if resp := f.reserve(t, f.reserveRequest(f.watermarkPermit(t, 9, 0), 1)); !resp.Success {
		t.Fatalf("a watermark that has accepted nothing was judged on its leaf: %s (%s)",
			resp.Error, resp.ErrorCode)
	}
}

// A conversation that has never sent has no leaf of its own to compare, which
// is the same answer as a conversation with no group state: the slot is not
// invented and the call is not refused on it.
func TestChatState_AWatermarkLeafIsIgnoredBeforeThisDeviceHasALeaf(t *testing.T) {
	f := newChatStateFixture(t)

	if resp := f.reserve(t, f.reserveRequest(f.watermarkPermit(t, 9, 0), 1)); !resp.Success {
		t.Fatalf("a conversation with no leaf was refused on a leaf: %s (%s)",
			resp.Error, resp.ErrorCode)
	}
}
