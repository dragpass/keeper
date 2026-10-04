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
// The harness (msgTestServerKey, msgTestVerifier, msgTestClock, newTestDeps)
// is shared with the message display tests in the same package; chatMarshal
// and the UUID constants below are shared with the other chat_state_* and
// mls_chat tests.

package handlers

import (
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
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const (
	chatOrgID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	chatConvID    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	chatAccountID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	chatOtherUUID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

	// chatNowUnix — a fixed "now" equal to the permit's issued_at, comfortably
	// inside the 300-second window.
	chatNowUnix = 1700000000
)

func chatMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

const chatStateClientMsgID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

// ────────────────────────────────────────────────────────────────────────
// Harness
// ────────────────────────────────────────────────────────────────────────

type chatStateFixture struct {
	deps  Deps
	log   *testdouble.MemoryLogger
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
		AccountID:                chatAccountID,
		OrgID:                    chatOrgID,
		ConversationID:           chatConvID,
		PendingRemovalAccountIDs: []string{},
		PendingLeafReplacements:  []proto.ChatStateLeafReplacement{},
		PendingDeviceRevocations: []proto.MLSDeviceRef{},
		IssuedAt:                 now,
		ExpiresAt:                now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion:         msgServerKeyVersion,
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

// readOutboxRequest is the permit-gated request the gate tests drive. Any
// permit-gated action runs the same openChatState gate; read_outbox is the one
// that needs no MLS library and writes nothing.
func (f *chatStateFixture) readOutboxRequest(p proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
	return proto.ChatStateReadOutboxRequest{
		Permit:          p,
		OrgID:           p.OrgID,
		ConversationID:  p.ConversationID,
		ClientMessageID: chatStateClientMsgID,
	}
}

func (f *chatStateFixture) readOutboxWith(t *testing.T, req proto.ChatStateReadOutboxRequest) proto.BaseResponse {
	t.Helper()
	return HandleChatStateReadOutbox(f.deps, chatMarshal(t, req))
}

func (f *chatStateFixture) readOutbox(t *testing.T, p proto.ChatStatePermit) proto.BaseResponse {
	t.Helper()
	return f.readOutboxWith(t, f.readOutboxRequest(p))
}

// seedConversation writes a sealed record for the owner's conversation
// through the store directly, which raises the keyring anchor the way any
// real write does.
func (f *chatStateFixture) seedConversation(t *testing.T, ownerAccountID string) {
	t.Helper()
	store, err := chatstate.Open(f.deps.Store, ownerAccountID)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.SaveGroupState(chatConvID, chatstate.ServerWatermark{}, []byte("group-state")); err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
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

// ────────────────────────────────────────────────────────────────────────
// The permit gate: nothing is opened before it passes
// ────────────────────────────────────────────────────────────────────────

func TestChatState_UnauthorizedCallsNeverOpenTheStateDirectory(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReadOutboxRequest
		code   string
	}{
		{
			name: "unsigned permit",
			mutate: func(_ *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				p := f.unsignedPermit()
				p.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
				return f.readOutboxRequest(p)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "watermark changed after signing",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				p.WatermarkNextApplication += 9
				return f.readOutboxRequest(p)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "server key version not pinned",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				p := f.unsignedPermit()
				p.ServerKeyVersion = msgServerKeyVersion + 1
				return f.readOutboxRequest(f.sign(t, p))
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "request names a different conversation than the permit",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				req := f.readOutboxRequest(p)
				req.ConversationID = chatOtherUUID
				return req
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit has expired",
			mutate: func(_ *testing.T, f *chatStateFixture, p proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				f.clock.advance(proto.ChatStatePermitTTLSeconds)
				return f.readOutboxRequest(p)
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit window is wider than the fixed span",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				p := f.unsignedPermit()
				p.ExpiresAt = p.IssuedAt + 2*proto.ChatStatePermitTTLSeconds
				return f.readOutboxRequest(f.sign(t, p))
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
		{
			name: "permit is issued too far in the future",
			mutate: func(t *testing.T, f *chatStateFixture, _ proto.ChatStatePermit) proto.ChatStateReadOutboxRequest {
				p := f.unsignedPermit()
				p.IssuedAt += 60
				p.ExpiresAt = p.IssuedAt + proto.ChatStatePermitTTLSeconds
				return f.readOutboxRequest(f.sign(t, p))
			},
			code: proto.ChatStateErrorCodeNotAuthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChatStateFixture(t)
			req := tc.mutate(t, f, f.permit(t))
			assertChatStateFailure(t, f.readOutboxWith(t, req), tc.code)
			f.assertStateRootAbsent(t)
		})
	}
}

func TestChatState_MalformedRequestsNeverOpenTheStateDirectory(t *testing.T) {
	f := newChatStateFixture(t)
	base := chatMarshal(t, f.readOutboxRequest(f.permit(t)))

	var object map[string]json.RawMessage
	if err := json.Unmarshal(base, &object); err != nil {
		t.Fatalf("unmarshal base request: %v", err)
	}

	withExtra := cloneJSONObject(object)
	withExtra["unexpected"] = json.RawMessage(`1`)

	missingMessageID := cloneJSONObject(object)
	delete(missingMessageID, "client_message_id")

	cases := []struct {
		name    string
		payload json.RawMessage
	}{
		{"unknown field", chatMarshal(t, withExtra)},
		{"missing field", chatMarshal(t, missingMessageID)},
		{
			// A duplicate key cannot be produced by marshalling a map, and it
			// is the case that matters most here: json.Unmarshal would keep the
			// last value, so the signature would cover one conversation and the
			// store would open another.
			"duplicate conversation_id",
			json.RawMessage(`{"permit":{},"org_id":"` + chatOrgID +
				`","conversation_id":"` + chatConvID +
				`","conversation_id":"` + chatOtherUUID +
				`","client_message_id":"` + chatStateClientMsgID + `"}`),
		},
		{"over the size cap", json.RawMessage(`{"pad":"` + strings.Repeat("a", proto.ChatStateMaxRequestBytes) + `"}`)},
		{"empty payload", json.RawMessage(``)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := HandleChatStateReadOutbox(f.deps, tc.payload)
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

// ────────────────────────────────────────────────────────────────────────
// The authorized flow
// ────────────────────────────────────────────────────────────────────────

func TestChatState_ReadOutboxReportsAMissingEntry(t *testing.T) {
	f := newChatStateFixture(t)
	f.seedConversation(t, chatAccountID)

	assertChatStateFailure(t, f.readOutbox(t, f.permit(t)), proto.ChatStateErrorCodeNotFound)
}

// TestChatState_OwnerComesFromThePermit checks the partitioning the handler
// relies on: two accounts on one device share a state root and must not share a
// chain. The request never names an owner, so the only way this can go wrong is
// the handler reading it from somewhere other than the permit.
//
// The first account's record is deleted under its live anchor, so its own
// permit is refused as a rewind. The second account's permit, for the same
// conversation, has to land on a store that never held anything.
func TestChatState_OwnerComesFromThePermit(t *testing.T) {
	f := newChatStateFixture(t)
	f.seedConversation(t, chatAccountID)
	removeSealedRecords(t, f.root)

	otherUnsigned := f.unsignedPermit()
	otherUnsigned.AccountID = chatOtherUUID
	other := f.sign(t, otherUnsigned)

	assertChatStateFailure(t, f.readOutbox(t, other), proto.ChatStateErrorCodeNotFound)
	assertChatStateFailure(t, f.readOutbox(t, f.permit(t)), proto.ChatStateErrorCodeRekeyRequired)
}

// ────────────────────────────────────────────────────────────────────────
// Rollback and erasure at the protocol edge
// ────────────────────────────────────────────────────────────────────────

// TestChatState_ADeletedStateFileIsRefusedAsARewind removes the sealed file
// while the keyring anchor still remembers the generation it authorized. That
// is the shape of a restore: the anchor is the surviving witness, and the
// action has to close with the code that means "establish a new epoch" rather
// than quietly treat the conversation as new.
func TestChatState_ADeletedStateFileIsRefusedAsARewind(t *testing.T) {
	f := newChatStateFixture(t)
	f.seedConversation(t, chatAccountID)
	permit := f.permit(t)

	removeSealedRecords(t, f.root)

	assertChatStateFailure(t, f.readOutbox(t, permit), proto.ChatStateErrorCodeRekeyRequired)
	// The refusal latches: a retry is not a way out.
	assertChatStateFailure(t, f.readOutbox(t, permit), proto.ChatStateErrorCodeRekeyRequired)
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
	f.seedConversation(t, chatAccountID)

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
	assertChatStateFailure(t, f.readOutbox(t, f.permit(t)), proto.ChatStateErrorCodeNotFound)
}

func TestChatState_PurgeRejectsAMalformedOwner(t *testing.T) {
	f := newChatStateFixture(t)
	assertChatStateFailure(t, f.purge(t, "not-a-uuid"), proto.ChatStateErrorCodeInvalidInput)
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
