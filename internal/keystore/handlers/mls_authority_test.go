package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A commit attestation is bound to the conversation, the epoch and the exact
// Commit bytes. A malicious server replaying one row's attestation for
// another Commit, another epoch or another conversation gets a refusal, not
// a member set.
func TestCommitMembers_TheAttestationIsBoundToItsCommit(t *testing.T) {
	f := newChatStateFixture(t)
	commit := []byte("the commit that produced epoch 3")
	sum := sha256.Sum256(commit)
	a := proto.MLSCommitAttestation{
		MemberAccountIDs: []string{chatAccountID, chatOrgID},
		ServerKeyVersion: msgServerKeyVersion,
	}
	slices.Sort(a.MemberAccountIDs)
	sig, err := crypto.SignData(f.key, proto.MLSCommitAttestationCanonical(chatConvID, 3, hex.EncodeToString(sum[:]), a))
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	if !verifyCommitAttestation(f.deps, chatConvID, 3, commit, &a) {
		t.Fatal("a genuine attestation did not verify")
	}
	for name, tc := range map[string]struct {
		conv   string
		epoch  uint64
		commit []byte
	}{
		"another commit":       {chatConvID, 3, []byte("a different commit for epoch 3")},
		"another epoch":        {chatConvID, 4, commit},
		"another conversation": {chatOrgID, 3, commit},
	} {
		if verifyCommitAttestation(f.deps, tc.conv, tc.epoch, tc.commit, &a) {
			t.Fatalf("%s: the attestation verified", name)
		}
	}
	edited := a
	edited.MemberAccountIDs = []string{chatAccountID}
	if verifyCommitAttestation(f.deps, chatConvID, 3, commit, &edited) {
		t.Fatal("an edited member set verified")
	}
	if !verifyCommitAttestation(f.deps, chatConvID, 3, commit, nil) {
		t.Fatal("an absent attestation must remain optional")
	}
}
