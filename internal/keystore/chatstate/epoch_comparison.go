package chatstate

import (
	"errors"
	"fmt"
)

const EpochComparisonDigestBytes = 32

type EpochComparisonCipher interface {
	Load(groupState []byte) error
	EpochComparisonDigest(conversationID []byte) (uint64, []byte, error)
}

type EpochComparison struct {
	Epoch  uint64
	Digest []byte
}

func (s *Store) CompareEpoch(conversationID string, wm ServerWatermark, cipher EpochComparisonCipher) (EpochComparison, error) {
	var out EpochComparison
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending != nil {
			return ErrCommitPending
		}
		if rec.RemovedFromGroup || len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		epoch, digest, err := cipher.EpochComparisonDigest([]byte(conversationID))
		if err != nil {
			return err
		}
		if epoch != rec.Epoch {
			return fmt.Errorf("%w: MLS epoch does not match the stored conversation epoch", ErrRekeyRequired)
		}
		if len(digest) != EpochComparisonDigestBytes {
			return errors.New("MLS epoch comparison digest has an invalid length")
		}
		out = EpochComparison{Epoch: epoch, Digest: digest}
		return nil
	})
	if err != nil {
		return EpochComparison{}, err
	}
	return out, nil
}
