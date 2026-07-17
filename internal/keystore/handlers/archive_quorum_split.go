// archive_quorum_split.go — quorum share creation: split + per-admin rewrap.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. This file covers the two
// steps that produce and re-target shares:
//
//   - HandleArchiveKeySplit: Shamir-split + hybrid-wrap shares, then delete the
//     org archive private key.
//   - HandleArchiveShareRewrap: an admin re-wraps their own share from their
//     account archive key to the recovery-session key.
//
// Key-material discipline: no raw share, private key, or Group DEK ever appears
// in a response. Reconstructed / unwrapped material lives only briefly in
// memory and is zeroized (secure.Zeroize) or held in memguard buffers wiped
// before returning.

package handlers

import (
	"crypto/rsa"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleArchiveKeySplit Shamir-splits the org archive private key into shares,
// hybrid-wraps each to a recipient (admin account archive) public key, then
// deletes the private key. Not idempotent: with no archive private key present
// it returns not_found. The public key slot is preserved, and the ACCOUNT
// archive slot (the admin receiving key) is never touched — only the ORG slot
// is wiped.
func HandleArchiveKeySplit(d Deps, req proto.ArchiveKeySplitRequest) proto.BaseResponse {
	d.Logger.Println("archive key split processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Parse all recipient keys before touching the archive key — fail early.
	pubs := make([]*rsa.PublicKey, len(req.RecipientPublicKeys))
	for i, pem := range req.RecipientPublicKeys {
		pk, err := crypto.ParsePublicKey(pem)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation,
				fmt.Sprintf("failed to parse recipient_public_keys[%d]: %v", i, err))
		}
		pubs[i] = pk
	}

	privKeyBuf, err := GetArchivePrivateKeySecure(d.Store)
	if err != nil {
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer privKeyBuf.Destroy()

	// Fingerprint of the key being split, derived from the private key itself
	// (not the pub slot) so the server can verify the coordinator split the
	// org's actual active archive key.
	splitPriv, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse archive private key: "+err.Error())
	}
	splitPubPEM, err := crypto.PublicKeyToPEM(&splitPriv.PublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to derive archive public key: "+err.Error())
	}
	keyFingerprint := fingerprintBase64Public(splitPubPEM)

	shares, err := crypto.SplitSecret(privKeyBuf.Bytes(), req.ThresholdN, len(pubs))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "shamir split failed: "+err.Error())
	}

	out := make([]proto.WrappedShare, len(shares))
	for i, s := range shares {
		serialized := crypto.SerializeShare(s)
		wrappedKey, ciphertext, wrapErr := crypto.HybridWrap(pubs[i], serialized)
		secure.Zeroize(serialized)
		secure.Zeroize(s.Y)
		if wrapErr != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure,
				fmt.Sprintf("hybrid wrap share %d failed: %v", i, wrapErr))
		}
		out[i] = proto.WrappedShare{
			ShareIndex:           int(s.X),
			WrappedKey:           wrappedKey,
			Ciphertext:           ciphertext,
			RecipientFingerprint: fingerprintBase64Public(req.RecipientPublicKeys[i]),
		}
	}

	// Success — delete the whole archive private key. It now exists only as the
	// shares just returned.
	if err := keychain.DeleteArchivePrivateKey(d.Store); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure,
			"delete archive private key after split failed: "+err.Error())
	}

	d.Logger.Printf("archive key split: %d shares (threshold %d), private key wiped",
		len(out), req.ThresholdN)
	return proto.BaseResponse{Success: true, Data: proto.ArchiveKeySplitResponseData{
		KeyFingerprint: keyFingerprint,
		Shares:         out,
	}}
}

// HandleArchiveShareRewrap re-wraps an admin's own hybrid-wrapped share from
// their ACCOUNT archive key (the dedicated per-account receiving slot — the
// key published to the account directory that the share was wrapped to at
// split time) to the recovery session public key, so the coordinator can
// combine it. The share plaintext lives only briefly in Keeper memory.
func HandleArchiveShareRewrap(d Deps, req proto.ArchiveShareRewrapRequest) proto.BaseResponse {
	d.Logger.Println("archive share rewrap processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	sessionPub, err := crypto.ParsePublicKey(req.SessionPublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse session_public_key: "+err.Error())
	}

	privKeyBuf, err := GetAccountArchivePrivateKeySecure(d.Store)
	if err != nil {
		return errs.Response(err) // not_found if this admin has no account archive key
	}
	defer privKeyBuf.Destroy()

	priv, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse account archive private key: "+err.Error())
	}

	share, err := crypto.HybridUnwrap(priv, req.WrappedKey, req.Ciphertext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share unwrap failed: "+err.Error())
	}
	defer secure.Zeroize(share)

	newWrappedKey, newCiphertext, err := crypto.HybridWrap(sessionPub, share)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "share rewrap failed: "+err.Error())
	}

	d.Logger.Println("archive share rewrap successful (raw share never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveShareRewrapResponseData{
		WrappedKey: newWrappedKey,
		Ciphertext: newCiphertext,
	}}
}
