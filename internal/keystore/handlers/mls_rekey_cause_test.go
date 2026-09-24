package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The status response carries the store's cause as its wire string, so the
// two vocabularies must stay one.
func TestRekeyCauseOfMapsEveryStoreCauseOntoTheWire(t *testing.T) {
	for cause, want := range map[chatstate.RekeyCause]string{
		chatstate.RekeyCauseRollback:         proto.ChatStateRekeyCauseRollback,
		chatstate.RekeyCauseStateMissing:     proto.ChatStateRekeyCauseStateMissing,
		chatstate.RekeyCauseWatermarkAhead:   proto.ChatStateRekeyCauseWatermarkAhead,
		chatstate.RekeyCauseAnchorUnreadable: proto.ChatStateRekeyCauseAnchorUnreadable,
		"":                                   proto.ChatStateRekeyCauseUnknown,
	} {
		if got := rekeyCauseOf(chatstate.ConversationStatus{NeedsRekey: true, RekeyCause: cause}); got != want {
			t.Fatalf("cause %q = %q, want %q", cause, got, want)
		}
	}
	if got := rekeyCauseOf(chatstate.ConversationStatus{RekeyCause: chatstate.RekeyCauseRollback}); got != "" {
		t.Fatalf("an unlatched status reported cause %q", got)
	}
}
