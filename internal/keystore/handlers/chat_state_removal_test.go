// chat_state_removal_test.go — the permit's pending-removal slot at the
// protocol edge (design §6.4.1 S-1). What the latch does with the list is
// chatstate's and internal/keystore/mls's to test; this file is the part that
// decides whether a list reaches the store at all.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	chatRemovedA = "55555555-5555-4555-8555-555555555555"
	chatRemovedB = "66666666-6666-4666-8666-666666666666"
)

// A permit signed over the 12-item v2 canonical does not verify against the v3
// bytes, and a v2-shaped request (no pending slot) does not decode. Either way
// the state directory is never opened.
func TestChatState_AV2PermitIsRefused(t *testing.T) {
	f := newChatStateFixture(t)
	p := f.unsignedPermit()
	v2 := strings.Join([]string{
		proto.ChatStatePermitDomain, "2", p.AccountID, p.OrgID, p.ConversationID,
		"0", "0", "0", "0",
		strconv.FormatInt(p.IssuedAt, 10), strconv.FormatInt(p.ExpiresAt, 10),
		strconv.FormatUint(uint64(p.ServerKeyVersion), 10),
	}, "|")
	sig, err := crypto.SignData(f.key, v2)
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	assertChatStateFailure(t, f.reserve(t, f.reserveRequest(p, 1)), proto.ChatStateErrorCodeNotAuthorized)
	f.assertStateRootAbsent(t)

	var object map[string]json.RawMessage
	if err := json.Unmarshal(chatMarshal(t, f.reserveRequest(p, 1)), &object); err != nil {
		t.Fatal(err)
	}
	var permit map[string]json.RawMessage
	if err := json.Unmarshal(object["permit"], &permit); err != nil {
		t.Fatal(err)
	}
	delete(permit, "pending_removal_account_ids")
	object["permit"] = chatMarshal(t, permit)
	resp := HandleChatStateReserveSend(f.deps, chatMarshal(t, object))
	assertChatStateFailure(t, resp, proto.ChatStateErrorCodeInvalidInput)
	f.assertStateRootAbsent(t)
}

// A malformed list is refused even when the server signed exactly those bytes:
// the Keeper never repairs one into something it would then act on.
func TestChatState_AMalformedPendingListIsRefused(t *testing.T) {
	over := make([]string, 0, proto.ChatStateMaxPendingRemovals+1)
	for i := 0; i <= proto.ChatStateMaxPendingRemovals; i++ {
		over = append(over, fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1))
	}
	for name, ids := range map[string][]string{
		"null":           nil,
		"unsorted":       {chatRemovedB, chatRemovedA},
		"duplicated":     {chatRemovedA, chatRemovedA},
		"uppercase":      {"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
		"over the bound": over,
	} {
		t.Run(name, func(t *testing.T) {
			f := newChatStateFixture(t)
			p := f.unsignedPermit()
			p.PendingRemovalAccountIDs = ids
			resp := f.reserve(t, f.reserveRequest(f.sign(t, p), 1))
			assertChatStateFailure(t, resp, proto.ChatStateErrorCodeInvalidInput)
			f.assertStateRootAbsent(t)
		})
	}
}

// A well-formed list verifies, and a conversation with no MLS group has nothing
// for it to latch: the pre-MLS reserve path carries on as before.
func TestChatState_ASignedListReachesAConversationWithoutAGroupHarmlessly(t *testing.T) {
	f := newChatStateFixture(t)
	p := f.unsignedPermit()
	p.PendingRemovalAccountIDs = []string{chatRemovedA, chatRemovedB}
	resp := f.reserve(t, f.reserveRequest(f.sign(t, p), 2))
	if got := reservationData(t, resp); got.Count != 2 {
		t.Fatalf("reservation = %+v", got)
	}
}

func TestChatState_ARotationPendingRefusalHasItsOwnCode(t *testing.T) {
	f := newChatStateFixture(t)
	resp := chatStateFailure(f.deps, "send", fmt.Errorf("wrapped: %w", chatstate.ErrRotationPending))
	assertChatStateFailure(t, resp, proto.ChatMLSErrorCodeRotationPending)
}
