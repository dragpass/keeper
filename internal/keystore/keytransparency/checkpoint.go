package keytransparency

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	formatlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

var (
	ErrInvalidCheckpoint  = errors.New("key transparency checkpoint is invalid")
	ErrWitnessQuorum      = errors.New("key transparency witness quorum is not met")
	ErrCheckpointRollback = errors.New("key transparency checkpoint rollback detected")
	ErrCheckpointFork     = errors.New("key transparency checkpoint fork detected")
	ErrConsistencyProof   = errors.New("key transparency consistency proof is invalid")
)

type Trust struct {
	Origin           string
	LogVerifier      note.Verifier
	WitnessVerifiers []note.Verifier
	Quorum           int
}

type CheckpointEvidence struct {
	Checkpoint       []byte
	ConsistencyProof [][]byte
}

type CheckpointAnchor struct {
	Version int    `json:"version"`
	Origin  string `json:"origin"`
	Size    uint64 `json:"size"`
	Root    []byte `json:"root"`
}

type VerifiedCheckpoint struct {
	Checkpoint CheckpointAnchor
	SignedNote *note.Note
}

const commitmentDomain = "dragpass.kt.leaf.v1\x00"

func VerifyAndPersist(store keychain.SecretStore, trust Trust, evidence CheckpointEvidence) (*VerifiedCheckpoint, error) {
	return verifyAndPersist(store, trust, evidence, nil)
}

func VerifyAndPersistStatement(
	store keychain.SecretStore,
	trust Trust,
	evidence CheckpointEvidence,
	statement, salt []byte,
	leafIndex uint64,
	inclusionNodes [][]byte,
) (*VerifiedCheckpoint, error) {
	if len(statement) == 0 || len(statement) > 64*1024 || len(salt) != 32 {
		return nil, ErrInvalidCheckpoint
	}
	input := make([]byte, 0, len(commitmentDomain)+len(salt)+4+len(statement))
	input = append(input, commitmentDomain...)
	input = append(input, salt...)
	input = binary.BigEndian.AppendUint32(input, uint32(len(statement)))
	input = append(input, statement...)
	commitment := sha256.Sum256(input)
	leafHash := rfc6962.DefaultHasher.HashLeaf(commitment[:])
	return verifyAndPersist(store, trust, evidence, func(anchor CheckpointAnchor) error {
		return VerifyInclusion(anchor, leafIndex, leafHash, inclusionNodes)
	})
}

func verifyAndPersist(
	store keychain.SecretStore,
	trust Trust,
	evidence CheckpointEvidence,
	verifyEntry func(CheckpointAnchor) error,
) (*VerifiedCheckpoint, error) {
	var verified *VerifiedCheckpoint
	err := keychain.UpdateKeyTransparencyCheckpoint(store, func(stored *keychain.KeyTransparencyCheckpoint) (keychain.KeyTransparencyCheckpoint, error) {
		previous := CheckpointAnchor{}
		if stored != nil {
			previous = CheckpointAnchor{Version: stored.Version, Origin: stored.Origin, Size: stored.Size, Root: bytes.Clone(stored.Root)}
		}
		var err error
		verified, err = VerifyCheckpoint(trust, evidence, previous)
		if err != nil {
			return keychain.KeyTransparencyCheckpoint{}, err
		}
		if verifyEntry != nil {
			if err := verifyEntry(verified.Checkpoint); err != nil {
				return keychain.KeyTransparencyCheckpoint{}, ErrInvalidCheckpoint
			}
		}
		return keychain.KeyTransparencyCheckpoint{
			Version: verified.Checkpoint.Version,
			Origin:  verified.Checkpoint.Origin,
			Size:    verified.Checkpoint.Size,
			Root:    bytes.Clone(verified.Checkpoint.Root),
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return verified, nil
}

func VerifyCheckpoint(trust Trust, evidence CheckpointEvidence, previous CheckpointAnchor) (*VerifiedCheckpoint, error) {
	if trust.Origin == "" || trust.LogVerifier == nil || trust.Quorum < 1 || trust.Quorum > len(trust.WitnessVerifiers) {
		return nil, ErrInvalidCheckpoint
	}
	verifiers := append([]note.Verifier(nil), trust.WitnessVerifiers...)
	checkpoint, _, signed, err := formatlog.ParseCheckpoint(
		evidence.Checkpoint, trust.Origin, trust.LogVerifier, verifiers...,
	)
	if err != nil || checkpoint == nil || signed == nil || len(checkpoint.Hash) != 32 {
		return nil, ErrInvalidCheckpoint
	}
	witnessNames := make(map[string]uint32, len(verifiers))
	for _, verifier := range verifiers {
		if verifier == nil || verifier.Name() == "" {
			return nil, ErrInvalidCheckpoint
		}
		witnessNames[verifier.Name()] = verifier.KeyHash()
	}
	seen := make(map[string]struct{}, len(signed.Sigs))
	for _, sig := range signed.Sigs {
		if keyHash, ok := witnessNames[sig.Name]; ok && keyHash == sig.Hash {
			seen[sig.Name] = struct{}{}
		}
	}
	if len(seen) < trust.Quorum {
		return nil, ErrWitnessQuorum
	}
	if previous.Version != 0 {
		if previous.Origin != trust.Origin {
			return nil, ErrInvalidCheckpoint
		}
		if checkpoint.Size < previous.Size {
			return nil, ErrCheckpointRollback
		}
		if checkpoint.Size == previous.Size {
			if !bytes.Equal(checkpoint.Hash, previous.Root) {
				return nil, ErrCheckpointFork
			}
		} else if err := proof.VerifyConsistency(
			rfc6962.DefaultHasher,
			previous.Size,
			checkpoint.Size,
			evidence.ConsistencyProof,
			previous.Root,
			checkpoint.Hash,
		); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConsistencyProof, err)
		}
	} else if checkpoint.Size == 0 {
		return nil, ErrInvalidCheckpoint
	}
	return &VerifiedCheckpoint{
		Checkpoint: CheckpointAnchor{Version: 1, Origin: trust.Origin, Size: checkpoint.Size, Root: bytes.Clone(checkpoint.Hash)},
		SignedNote: signed,
	}, nil
}

func VerifyInclusion(anchor CheckpointAnchor, leafIndex uint64, leafHash []byte, nodes [][]byte) error {
	if anchor.Version != 1 || anchor.Origin == "" || len(anchor.Root) != 32 || leafIndex >= anchor.Size {
		return ErrInvalidCheckpoint
	}
	return proof.VerifyInclusion(rfc6962.DefaultHasher, leafIndex, anchor.Size, leafHash, nodes, anchor.Root)
}

func EncodeAnchor(anchor CheckpointAnchor) (string, error) {
	if anchor.Version != 1 || anchor.Origin == "" || anchor.Size == 0 || len(anchor.Root) != 32 {
		return "", ErrInvalidCheckpoint
	}
	raw, err := json.Marshal(anchor)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func DecodeAnchor(encoded string) (CheckpointAnchor, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return CheckpointAnchor{}, ErrInvalidCheckpoint
	}
	var anchor CheckpointAnchor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&anchor); err != nil || anchor.Version != 1 || anchor.Origin == "" || anchor.Size == 0 || len(anchor.Root) != 32 {
		return CheckpointAnchor{}, ErrInvalidCheckpoint
	}
	return anchor, nil
}
