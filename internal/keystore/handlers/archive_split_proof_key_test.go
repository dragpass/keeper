package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// expectedProofPublicKey re-derives a share's proof key from the plan's
// literal derivation rather than from Keeper's helper, so a change to the
// domain, field order or encoding fails here.
func expectedProofPublicKey(t *testing.T, serializedShare []byte, operationID string, index int) []byte {
	t.Helper()
	info := "dragpass.archive.share.proof-key|1|36:" + operationID + "|1:" + string(rune('0'+index))
	seed, err := hkdf.Key(sha256.New, serializedShare, nil, info, ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func TestArchiveKeySplitReturnsShareDerivedProofKeys(t *testing.T) {
	f := newSplitFixture(t)
	response := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request))
	if !response.Success {
		t.Fatalf("authorized split refused: %s", response.Error)
	}
	data := response.Data.(proto.ArchiveKeySplitResponseData)
	seen := map[string]bool{}
	for i, share := range data.Shares {
		got, err := base64.StdEncoding.DecodeString(share.ProofPublicKey)
		if err != nil || len(got) != ed25519.PublicKeySize || seen[share.ProofPublicKey] {
			t.Fatalf("share %d proof public key is missing, malformed or repeated", i)
		}
		seen[share.ProofPublicKey] = true
		priv, err := crypto.ParsePrivateKey(f.admins[i].PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := crypto.HybridUnwrap(priv, share.WrappedKey, share.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if want := expectedProofPublicKey(t, opened, splitTestOperation, share.ShareIndex); !bytes.Equal(got, want) {
			t.Fatalf("share %d proof public key is not derived from the share", i)
		}
	}
}

func TestArchiveKeySplitRetryReturnsSameProofKeysFromJournal(t *testing.T) {
	f := newSplitFixture(t)
	first := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request))
	second := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request))
	if !first.Success || !second.Success || !reflect.DeepEqual(first.Data, second.Data) {
		t.Fatal("retry under a fresh decision did not return the stored split result")
	}
	slot, _, _, err := keychain.FindArchiveKey(f.store, keychain.OrgArchiveActiveCandidates(f.v.OrgID))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.store.Get(config.Service, "archive_quorum_split_pending:"+slot.PrivateAccount)
	if err != nil {
		t.Fatal(err)
	}
	var journal archiveSplitJournal
	if err := json.Unmarshal([]byte(raw), &journal); err != nil {
		t.Fatal(err)
	}
	for i, share := range first.Data.(proto.ArchiveKeySplitResponseData).Shares {
		if share.ProofPublicKey == "" || journal.Result.Shares[i].ProofPublicKey != share.ProofPublicKey {
			t.Fatalf("journal does not hold share %d's proof public key", i)
		}
	}
	if journal.Binding.ConfigDigest != splitTestConfig || journal.Binding.AccountID != f.v.AccountID {
		t.Fatal("journal does not hold the decision binding")
	}
	changed := f.request
	changed.ConfigDigest = "ab" + splitTestConfig[2:]
	if r := HandleArchiveKeySplit(f.deps, f.authorize(t, changed)); r.Success {
		t.Fatal("same operation under another configuration returned the stored shares")
	}
}
