//go:build mls && cgo

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Bob reads more messages than the local history ring holds, then opens the
// conversation again from seq 1, as the app does. The seqs the ring evicted
// were opened once and their keys are gone; they come back as
// history_unavailable items, the rest from history, and a message nobody has
// opened yet in the same page is still opened with MLS.
func TestMLSChatE2E_ARereadPastTheHistoryRingMarksTheEvictedItems(t *testing.T) {
	c := newDM(t)
	const sent = chatstate.DefaultHistoryMaxEntries + 2
	var page []proto.MLSDisplayMessage
	for i := range sent {
		page = append(page, c.send(c.alice, i+1, 1, "m"))
	}
	if got := c.bob.decrypt(page...); len(got.Items) != sent {
		t.Fatalf("first read returned %d items", len(got.Items))
	}

	fresh := c.send(c.alice, sent+1, 1, "fresh")
	resp := c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(append(page, fresh)...))
	if !resp.Success {
		t.Fatalf("re-reading from seq 1 refused the page: %s (%s)", resp.Error, resp.ErrorCode)
	}
	got := resp.Data.(proto.MLSDisplayResponseData)
	for i, item := range got.Items {
		switch {
		case i < 2:
			if item.State != proto.MLSDisplayItemStateHistoryUnavailable || got.PlaintextB64[i] != "" ||
				item.Seq != page[i].Seq || item.SenderAccountID != "" {
				t.Fatalf("evicted item %d = %+v %q", i, item, got.PlaintextB64[i])
			}
		case i < sent:
			assertShown(t, got, i, "m", c.alice, true)
		default:
			assertShown(t, got, i, "fresh", c.alice, false)
		}
	}
}
