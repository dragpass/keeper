// archive_quorum.go — org archive-key admin quorum (Shamir N-of-M) handlers.
//
// These implement the break-glass recovery flow where the org archive private
// key is Shamir-split across M admin devices and reconstructed only inside the
// coordinator's Keeper during a recovery session:
//
//   - HandleArchiveKeySplit: split + hybrid-wrap shares, then delete the key.
//   - HandleArchiveShareRewrap: an admin re-wraps their share to the session key.
//   - HandleArchiveSessionBegin / _End: session keypair lifecycle.
//   - HandleArchiveQuorumCombineAndRewrap: reconstruct + re-grant OLD DEKs.
//
// No reconstructed private key, raw share, or raw Group DEK is ever in a
// response — the same raw-free discipline as the other admin composite actions.
// Reconstructed material lives only in memguard buffers wiped before returning.

package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/awnumar/memguard"

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

// HandleArchiveSessionBegin generates the coordinator's ephemeral
// recovery-session keypair and returns its public key. Overwrites any prior
// session key (a new session supersedes an abandoned one).
func HandleArchiveSessionBegin(d Deps, req proto.ArchiveSessionBeginRequest) proto.BaseResponse {
	d.Logger.Println("archive session begin processing...")

	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive session keygen failed: "+err.Error())
	}

	privBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privBuf.Destroy()

	if err := keychain.SaveArchiveSessionPrivateKey(d.Store, string(privBuf.Bytes())); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session priv key failed: "+err.Error())
	}
	if err := keychain.SaveArchiveSessionPublicKey(d.Store, keyPair.PublicKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive session pub key failed: "+err.Error())
	}

	d.Logger.Println("archive session begin: ephemeral keypair created")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionBeginResponseData{
		SessionPublicKey: keyPair.PublicKey,
		Fingerprint:      fingerprintBase64Public(keyPair.PublicKey),
	}}
}

// HandleArchiveSessionEnd destroys the recovery-session keypair. Idempotent —
// ended=false when no session was present.
func HandleArchiveSessionEnd(d Deps, req proto.ArchiveSessionEndRequest) proto.BaseResponse {
	d.Logger.Println("archive session end processing...")

	existing, _ := keychain.GetArchiveSessionPrivateKey(d.Store)
	ended := existing != ""

	_ = keychain.DeleteArchiveSessionPrivateKey(d.Store)
	_ = keychain.DeleteArchiveSessionPublicKey(d.Store)

	return proto.BaseResponse{Success: true, Data: proto.ArchiveSessionEndResponseData{Ended: ended}}
}

// HandleArchiveQuorumCombineAndRewrap reconstructs the archive private key from
// re-wrapped shares, unwraps the OLD Group DEK with it, and re-wraps the DEK to
// the target members. All reconstructed key material is wiped before the
// response, which carries only the new per-recipient wraps.
func HandleArchiveQuorumCombineAndRewrap(d Deps, req proto.ArchiveQuorumCombineAndRewrapRequest) proto.BaseResponse {
	d.Logger.Println("archive quorum combine and rewrap processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	pubs := make([]*rsa.PublicKey, len(req.RecipientPublicKeys))
	for i, pem := range req.RecipientPublicKeys {
		pk, err := crypto.ParsePublicKey(pem)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation,
				fmt.Sprintf("failed to parse recipient_public_keys[%d]: %v", i, err))
		}
		pubs[i] = pk
	}

	wrappedOldDEK, err := base64.StdEncoding.DecodeString(req.WrappedOldDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode wrapped_old_dek_b64: "+err.Error())
	}

	sessionBuf, err := GetArchiveSessionPrivateKeySecure(d.Store)
	if err != nil {
		return errs.Response(err) // not_found if no session is open
	}
	defer sessionBuf.Destroy()

	sessionPriv, err := crypto.ParsePrivateKey(string(sessionBuf.Bytes()))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse session private key: "+err.Error())
	}

	// Unwrap + deserialize each re-wrapped share.
	shares := make([]crypto.Share, 0, len(req.RewrappedShares))
	defer func() {
		for _, sh := range shares {
			secure.Zeroize(sh.Y)
		}
	}()
	for i, s := range req.RewrappedShares {
		raw, unwrapErr := crypto.HybridUnwrap(sessionPriv, s.WrappedKey, s.Ciphertext)
		if unwrapErr != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure,
				fmt.Sprintf("rewrapped share %d unwrap failed: %v", i, unwrapErr))
		}
		share, dsErr := crypto.DeserializeShare(raw)
		secure.Zeroize(raw)
		if dsErr != nil {
			return errs.CodeResponse(errs.ErrCodeValidation,
				fmt.Sprintf("rewrapped share %d malformed: %v", i, dsErr))
		}
		shares = append(shares, share)
	}

	secretBytes, err := crypto.CombineShares(shares)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "shamir combine failed: "+err.Error())
	}
	archiveBuf := memguard.NewBufferFromBytes(secretBytes)
	defer archiveBuf.Destroy()

	archivePriv, err := crypto.ParsePrivateKey(string(archiveBuf.Bytes()))
	if err != nil {
		// Below threshold or tampered shares reconstruct a wrong secret that is
		// not a valid PEM key — a well-formed failure signal, no leak.
		return errs.CodeResponse(errs.ErrCodeCryptoFailure,
			"reconstructed archive key failed to parse (insufficient or invalid shares)")
	}

	groupDEK, err := crypto.DecryptData(archivePriv, wrappedOldDEK)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt of OLD DEK failed: "+err.Error())
	}
	defer secure.Zeroize(groupDEK)

	if len(groupDEK) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "unexpected group dek length (want 32)")
	}

	grants := make([]proto.QuorumRewrapGrant, len(pubs))
	for i, pk := range pubs {
		enc, encErr := crypto.EncryptData(pk, groupDEK)
		if encErr != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure,
				fmt.Sprintf("re-wrap for recipient %d failed: %v", i, encErr))
		}
		grants[i] = proto.QuorumRewrapGrant{
			RecipientFingerprint: fingerprintBase64Public(req.RecipientPublicKeys[i]),
			EncryptedGroupDEKB64: base64.StdEncoding.EncodeToString(enc),
		}
	}

	d.Logger.Printf("archive quorum combine and rewrap successful: %d grants (raw key material wiped)", len(grants))
	return proto.BaseResponse{Success: true, Data: proto.ArchiveQuorumCombineAndRewrapResponseData{Grants: grants}}
}
