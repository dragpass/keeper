// mls_authority.go — the signed statement the Commit authority rules read
// (chatstate/authority.go): the server's member-set attestation on a handshake
// row.

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// errAttestationRefused — a commit attestation that does not verify. Answered
// as CHAT_STATE_NOT_AUTHORIZED, like a permit whose signature fails.
var errAttestationRefused = errors.New("mls commit attestation does not verify")

// commitMembers verifies a handshake row's attestation for commit at epoch
// and returns the member set it signs. Nil in, nil out: a row without one is
// no evidence, which the rules read as such. A signature that does not verify
// is a refusal of the request, not a missing attestation, so a tampered row
// never reads as a legacy one.
func commitMembers(
	d Deps, conversationID string, epoch uint64, commit []byte, a *proto.MLSCommitAttestation,
) (*chatstate.ServerCommitMembers, bool) {
	if a == nil {
		return nil, true
	}
	sum := sha256.Sum256(commit)
	canonical := proto.MLSCommitAttestationCanonical(conversationID, epoch, hex.EncodeToString(sum[:]), *a)
	if err := d.ServerKeyVerifier.Verify(canonical, a.Signature, a.ServerKeyVersion); err != nil {
		return nil, false
	}
	return &chatstate.ServerCommitMembers{AccountIDs: a.MemberAccountIDs}, true
}
