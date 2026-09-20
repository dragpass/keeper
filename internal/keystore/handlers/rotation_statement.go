// rotation_statement.go — building a signed rotation statement (account key
// trust v1).
//
// Two flows produce one: the voluntary rotation prepare, and the RK24
// recovery. They differ in where the old private key is — the Keychain's
// active slot in one case, a memguard buffer behind a recovery handle in the
// other — and in the reason they may claim. Everything else is identical, so
// the assembly lives here once and each caller passes its two signers in.
//
// Recovery produces a statement at all because recovery changes the account
// public key (`ApplyRecovery` writes it). Without one, every peer who had
// pinned the recovering account would see an unexplained key change on their
// next wrap, and an ordinary recovery would lock the account out of invites,
// rotations, and DMs across the whole org.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §5, §6.6.

package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// rotationStatementInput is everything a statement needs. The two signers are
// closures so the caller keeps its private key material wherever it already
// lives — this file never sees a PEM of a private key.
type rotationStatementInput struct {
	accountID    string
	reason       string
	rotatedAt    int64
	oldPublicPEM string
	newPublicPEM string
	signOld      func(canonical string) (string, error)
	signNew      func(canonical string) (string, error)
}

// buildRotationStatement computes both fingerprints, renders the canonical,
// and collects the two signatures over it.
//
// The fingerprints are taken from the PEM bytes directly. Nothing is parsed
// and re-serialized first: a peer recomputes the fingerprint from the Base64
// PEM this statement carries, and a round trip through the parser could hand
// back bytes that differ from what the server stores.
func buildRotationStatement(in rotationStatementInput) (proto.KeyRotationStatement, error) {
	oldFingerprint := crypto.AccountKeyFingerprint([]byte(in.oldPublicPEM))
	newFingerprint := crypto.AccountKeyFingerprint([]byte(in.newPublicPEM))
	canonical := proto.KeyRotationCanonical(
		in.accountID, oldFingerprint, newFingerprint, in.rotatedAt, in.reason,
	)

	oldSignature, err := in.signOld(canonical)
	if err != nil {
		return proto.KeyRotationStatement{}, err
	}
	newSignature, err := in.signNew(canonical)
	if err != nil {
		return proto.KeyRotationStatement{}, err
	}

	return proto.KeyRotationStatement{
		AccountID:      in.accountID,
		OldFingerprint: oldFingerprint,
		NewFingerprint: newFingerprint,
		RotatedAt:      in.rotatedAt,
		Reason:         in.reason,
		OldPublicKey:   base64.StdEncoding.EncodeToString([]byte(in.oldPublicPEM)),
		NewPublicKey:   base64.StdEncoding.EncodeToString([]byte(in.newPublicPEM)),
		OldSignature:   oldSignature,
		NewSignature:   newSignature,
	}, nil
}
