//go:build mls && cgo

package dispatch

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// encryptBytes encrypts plaintext as this device without going through
// mls_encrypt, which refuses anything that is not text: what a client of
// another version, or a member running something other than this Keeper,
// can put in a message. The group state is not written back, so these must
// be this device's last sends in the test.
func (c *dm) encryptBytes(from *keeper, plaintexts ...[]byte) []proto.MLSDisplayMessage {
	t := from.t
	t.Helper()
	if from.root != "" {
		shared := os.Getenv(chatstate.RootEnvVar)
		os.Setenv(chatstate.RootEnvVar, from.root)
		defer os.Setenv(chatstate.RootEnvVar, shared)
	}
	store, err := chatstate.Open(from.store, from.id)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session, _, err := mls.NewDeviceSession(from.store)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	blob, err := store.LoadGroupState(e2eConv, chatstate.ServerWatermark{})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(blob); err != nil {
		t.Fatal(err)
	}
	var out []proto.MLSDisplayMessage
	for _, plaintext := range plaintexts {
		_, leaf, generation, err := session.SendPosition()
		if err != nil {
			t.Fatal(err)
		}
		declaration := fmt.Sprintf("dragpass.chat.mls|1|a|%d|%d", leaf, generation)
		ciphertext, err := session.Encrypt(plaintext, []byte(declaration))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, proto.MLSDisplayMessage{
			Seq: c.nextSeq(), CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		})
	}
	return out
}

func assertUnsupported(t *testing.T, got proto.MLSDisplayResponseData, i int, sender *keeper, fromHistory bool) {
	t.Helper()
	item := got.Items[i]
	if item.State != proto.MLSDisplayItemStateUnsupported || got.PlaintextB64[i] != "" ||
		item.SenderAccountID != sender.id || item.SenderDeviceID != e2eDevice ||
		item.FromHistory != fromHistory || item.ContentType != proto.ChatStateContentTypeApplication {
		t.Fatalf("message %d = %+v %q; want unsupported from %s (from_history=%v)",
			i, item, got.PlaintextB64[i], sender.id[:8], fromHistory)
	}
}

// Alice's client puts bytes that are not text in two messages: one that is
// not UTF-8 and one that is empty. Bob's page used to be refused whole, and
// every message after them never showed. Now each is answered as unsupported,
// under alice's name and with no plaintext, the page around them is shown,
// and a re-read answers the same from the local copy.
func TestMLSChatE2E_AMessageThatIsNotTextDoesNotRefuseThePage(t *testing.T) {
	c := newDM(t)
	before := c.send(c.alice, 1, 1, "before")
	after := c.send(c.alice, 2, 1, "after")
	crafted := c.encryptBytes(c.alice, []byte{0xff, 0xfe, 0x00, 0x80}, []byte{})
	notUTF8, empty := crafted[0], crafted[1]

	resp := c.bob.call(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(before, notUTF8, empty, after))
	if !resp.Success {
		t.Fatalf("a page holding a message that is not text was refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
	got := resp.Data.(proto.MLSDisplayResponseData)
	assertShown(t, got, 0, "before", c.alice, false)
	assertUnsupported(t, got, 1, c.alice, false)
	assertUnsupported(t, got, 2, c.alice, false)
	assertShown(t, got, 3, "after", c.alice, false)

	again := c.bob.decrypt(notUTF8, empty)
	assertUnsupported(t, again, 0, c.alice, true)
	assertUnsupported(t, again, 1, c.alice, true)
}
