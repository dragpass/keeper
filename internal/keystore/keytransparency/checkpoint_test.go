package keytransparency

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	formatlog "github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

func TestVerifyAndPersistRequiresQuorumAndMonotonicConsistency(t *testing.T) {
	logPrivate, logPublic, err := note.GenerateKey(rand.Reader, "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := note.NewSigner(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	logVerifier, err := note.NewVerifier(logPublic)
	if err != nil {
		t.Fatal(err)
	}
	witnessSigners := make([]note.Signer, 3)
	witnessVerifiers := make([]note.Verifier, 3)
	for i := range witnessSigners {
		private, public, err := note.GenerateKey(rand.Reader, string(rune('a'+i))+".witness")
		if err != nil {
			t.Fatal(err)
		}
		witnessSigners[i], err = formatnote.NewSignerForCosignatureV1(private)
		if err != nil {
			t.Fatal(err)
		}
		witnessVerifiers[i], err = formatnote.NewVerifierForCosignatureV1(public)
		if err != nil {
			t.Fatal(err)
		}
	}
	trust := Trust{
		Origin: "dragpass.test/log", LogVerifier: logVerifier, WitnessVerifiers: witnessVerifiers,
		Quorum: 2, MaxCheckpointAge: 24 * time.Hour, FutureSkew: 5 * time.Minute,
	}
	statement := []byte("signed account key binding")
	salt := bytes.Repeat([]byte{0x33}, 32)
	commitmentInput := append([]byte(commitmentDomain), salt...)
	commitmentInput = binary.BigEndian.AppendUint32(commitmentInput, uint32(len(statement)))
	commitmentInput = append(commitmentInput, statement...)
	commitment := sha256.Sum256(commitmentInput)
	leafA := rfc6962.DefaultHasher.HashLeaf(commitment[:])
	leafB := rfc6962.DefaultHasher.HashLeaf([]byte("commitment-b"))
	rootTwo := rfc6962.DefaultHasher.HashChildren(leafA, leafB)
	makeEvidence := func(size uint64, root []byte, witnesses ...note.Signer) CheckpointEvidence {
		checkpoint := formatlog.Checkpoint{Origin: trust.Origin, Size: size, Hash: root}
		raw, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, logSigner)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := note.Open(raw, note.VerifierList(logVerifier))
		if err != nil {
			t.Fatal(err)
		}
		for _, signer := range witnesses {
			raw, err = note.Sign(signed, signer)
			if err != nil {
				t.Fatal(err)
			}
			signed, err = note.Open(raw, note.VerifierList(append([]note.Verifier{logVerifier}, witnessVerifiers...)...))
			if err != nil {
				t.Fatal(err)
			}
		}
		return CheckpointEvidence{Checkpoint: raw}
	}
	first := makeEvidence(1, leafA, witnessSigners[0], witnessSigners[1])
	store := keychain.NewMemorySecretStore()
	verified, err := VerifyAndPersistStatement(store, trust, first, statement, salt, 0, nil)
	if err != nil {
		t.Fatalf("verify initial checkpoint: %v", err)
	}
	if verified.Checkpoint.Size != 1 {
		t.Fatalf("initial size = %d, want 1", verified.Checkpoint.Size)
	}
	if _, err := VerifyAndPersistStatement(store, trust, first, []byte("different statement"), salt, 0, nil); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("wrong statement error = %v, want ErrInvalidCheckpoint", err)
	}
	second := makeEvidence(2, rootTwo, witnessSigners[0], witnessSigners[2])
	second.ConsistencyProof = [][]byte{leafB}
	if _, err := VerifyAndPersistStatement(store, trust, second, statement, salt, 0, [][]byte{leafB}); err != nil {
		t.Fatalf("verify consistent update: %v", err)
	}
	if _, err := VerifyAndPersist(store, trust, first); !errors.Is(err, ErrCheckpointRollback) {
		t.Fatalf("rollback error = %v, want ErrCheckpointRollback", err)
	}
	anchor, found, err := keychain.GetKeyTransparencyCheckpoint(store)
	if err != nil || !found || anchor.Size != 2 || !bytes.Equal(anchor.Root, rootTwo) {
		t.Fatalf("anchor after rollback attempt = %#v, found=%v, err=%v", anchor, found, err)
	}
	withoutQuorum := makeEvidence(2, rootTwo, witnessSigners[0])
	if _, err := VerifyCheckpoint(trust, withoutQuorum, CheckpointAnchor{Version: 1, Origin: trust.Origin, Size: 2, Root: rootTwo}); !errors.Is(err, ErrWitnessQuorum) {
		t.Fatalf("quorum error = %v, want ErrWitnessQuorum", err)
	}
	if _, err := VerifyCheckpointAt(trust, first, CheckpointAnchor{}, time.Now().Add(25*time.Hour)); !errors.Is(err, ErrCheckpointFreshness) {
		t.Fatalf("stale checkpoint error = %v, want ErrCheckpointFreshness", err)
	}
	if _, err := VerifyCheckpointAt(trust, first, CheckpointAnchor{}, time.Now().Add(-6*time.Minute)); !errors.Is(err, ErrCheckpointFreshness) {
		t.Fatalf("future checkpoint error = %v, want ErrCheckpointFreshness", err)
	}
	missingFreshnessPolicy := trust
	missingFreshnessPolicy.MaxCheckpointAge = 0
	if _, err := VerifyCheckpoint(missingFreshnessPolicy, first, CheckpointAnchor{}); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("missing freshness policy error = %v, want ErrInvalidCheckpoint", err)
	}
	staleStore := keychain.NewMemorySecretStore()
	if _, err := verifyAndPersist(staleStore, trust, first, nil, time.Now().Add(25*time.Hour)); !errors.Is(err, ErrCheckpointFreshness) {
		t.Fatalf("persist stale checkpoint error = %v, want ErrCheckpointFreshness", err)
	}
	if _, found, err := keychain.GetKeyTransparencyCheckpoint(staleStore); err != nil || found {
		t.Fatalf("stale checkpoint changed anchor: found=%v err=%v", found, err)
	}
	fork := makeEvidence(2, bytes.Repeat([]byte{0x61}, 32), witnessSigners[0], witnessSigners[2])
	if _, err := VerifyCheckpoint(trust, fork, CheckpointAnchor{Version: 1, Origin: trust.Origin, Size: 2, Root: rootTwo}); !errors.Is(err, ErrCheckpointFork) {
		t.Fatalf("fork error = %v, want ErrCheckpointFork", err)
	}
}
