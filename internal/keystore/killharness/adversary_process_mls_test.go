//go:build mls && cgo

// A malicious client's Commit refused by the Keeper binary, and the refusal
// surviving a forced kill (wave 5c item 8). Mallory's device is the test-only
// adversary (mls/examples/adversary.rs: mls-rs with its permissive rules and
// Mallory's own leaf key), so the Commit is valid MLS signed by a real member;
// Alice's Keeper is the release entry point, every permit and attestation
// signed by the test server key. The in-process variants of the same refusals
// are internal/keystore/dispatch/mls_adversary_e2e_cgo_test.go.

package killharness

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const hMallory = "f6666666-6666-4666-8666-666666666666"

// fileKeyring reads a device's keyring file as a SecretStore, for the one
// thing the adversary needs from it: the leaf key it plays.
type fileKeyring map[string]string

func (k fileKeyring) Get(service, account string) (string, error) {
	v, ok := k[service+"|"+account]
	if !ok {
		return "", keychain.ErrSecretNotFound
	}
	return v, nil
}
func (fileKeyring) Set(string, string, string) error { return nil }
func (fileKeyring) Delete(string, string) error      { return nil }

func (d *device) keyring() map[string]string {
	d.t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.dir, "keyring.json"))
	if err != nil {
		d.t.Fatal(err)
	}
	var entries map[string]string
	if err := json.Unmarshal(raw, &entries); err != nil {
		d.t.Fatal(err)
	}
	return entries
}

// deviceState is what a refusal must leave as it was: every state file byte
// for byte, and every keyring entry, the anchor's latch fields aside.
type deviceState struct {
	files   map[string][]byte
	keyring map[string]string
}

func (d *device) state() deviceState {
	d.t.Helper()
	s := deviceState{files: map[string][]byte{}, keyring: map[string]string{}}
	if err := filepath.WalkDir(d.stateRoot(), func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasSuffix(path, ".lock") {
			return err
		}
		b, err := os.ReadFile(path)
		s.files[path] = b
		return err
	}); err != nil {
		d.t.Fatal(err)
	}
	for key, value := range d.keyring() {
		if strings.HasPrefix(key, config.Service+"|"+config.ChatStateAnchorPrefix) {
			var a chatstate.Anchor
			if err := json.Unmarshal([]byte(value), &a); err != nil {
				d.t.Fatal(err)
			}
			// The block is the one thing a refusal writes (anchor sync_block).
			a.SyncBlock = nil
			raw, err := json.Marshal(a)
			if err != nil {
				d.t.Fatal(err)
			}
			value = string(raw)
		}
		s.keyring[key] = value
	}
	return s
}

func assertSameState(t *testing.T, when string, before, after deviceState) {
	t.Helper()
	if !maps.EqualFunc(before.files, after.files, bytes.Equal) {
		t.Fatalf("%s: the state files changed", when)
	}
	if !maps.Equal(before.keyring, after.keyring) {
		t.Fatalf("%s: a keyring entry changed (a pin, a record, or the anchor's epoch or watermark)", when)
	}
}

// A plain member's Remove of Carol, built by the adversary, is refused by
// Alice's Keeper process, which stops at that epoch (unauthorized_commit
// naming Mallory, N3: a block, not a latch). The process is force-killed right
// after the refusal; the restarted one reports the same block, refuses the
// row again, and every state file and keyring entry is what it was before the
// Commit arrived, but for the anchor's sync_block.
func TestKeeperProcessRefusesAMaliciousClientsCommitAcrossAKill(t *testing.T) {
	alice, carol, mallory := newDevice(t, hAlice), newDevice(t, hCarol), newDevice(t, hMallory)
	a, c, m := alice.start("", 0), carol.start("", 0), mallory.start("", 0)
	a.enrol()
	c.enrol()
	m.enrol()
	m.in.Close()
	<-m.done
	leaf, found, err := keychain.GetMLSLeafKey(fileKeyring(mallory.keyring()))
	if err != nil || !found {
		t.Fatalf("mallory's leaf key: %v", err)
	}
	adv := mlsadversary.Start(t, leaf, true)

	id := alice.nextCommitID()
	var built proto.MLSCommitResponseData
	a.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: hOrg, ConversationID: hConv, ClientCommitID: id,
		Members: []proto.MLSMemberKeyPackage{c.keyPackage(), {
			AccountID: hMallory, DeviceID: hDevice, KeyPackageB64: base64.StdEncoding.EncodeToString(adv.KeyPackage()),
		}},
		Roles: &proto.MLSRoleSet{Kind: proto.MLSRolesKindRoom,
			Entries: []proto.MLSRoleEntry{{AccountID: hAlice, Role: proto.MLSRoleOwner}}},
	}, &built)
	a.must(proto.MLSCommitConfirm, alice.confirmRequest(id), nil)
	c.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: hOrg, ConversationID: hConv, WelcomeB64: built.WelcomeB64,
	}, nil)
	c.in.Close()
	<-c.done
	welcome, err := base64.StdEncoding.DecodeString(built.WelcomeB64)
	if err != nil {
		t.Fatal(err)
	}
	adv.Join(welcome)

	commit, _ := adv.Build(mlsadversary.Commit{Removes: []uint32{adv.IndexOf(hCarol, hDevice)}})
	commitB64 := base64.StdEncoding.EncodeToString(commit)
	req := alice.attestedProcess(2, 2, commitB64, hAlice, hCarol, hMallory)

	before := alice.state()
	got := blockDetail(t, a.call(proto.MLSProcess, req))
	if got.Cause != proto.ChatStateRekeyCauseUnauthorizedCommit || got.Epoch != 2 || got.CommitterAccountID != hMallory {
		t.Fatalf("block detail = %+v", got)
	}
	assertSameState(t, "after the refusal", before, alice.state())
	a.killAndAssertKilled()
	assertSameState(t, "after the kill", before, alice.state())

	a = alice.start("", 0)
	status := a.status()
	if status.NeedsRekey || status.SyncBlocked == nil || status.SyncBlocked.CommitterAccountID != hMallory || status.Epoch != 1 {
		t.Fatalf("status after the restart = %+v", status)
	}
	a.refused(proto.MLSProcess, alice.attestedProcess(2, 2, commitB64, hAlice, hCarol, hMallory),
		proto.ChatMLSErrorCodeRowRefused)
	a.refused(proto.MLSEncrypt, alice.encryptRequest(messageID(3), 1, "not on top of it"), proto.ChatMLSErrorCodeSyncBlocked)
	assertSameState(t, "after the restart and a retry", before, alice.state())
	if anchor := alice.anchor(); anchor.Epoch != 1 || anchor.NeedsRekey || anchor.SyncBlock == nil {
		t.Fatalf("anchor after the restart = %+v", anchor)
	}
}
