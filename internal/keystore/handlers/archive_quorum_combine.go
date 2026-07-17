// archive_quorum_combine.go — quorum reconstruction + Group DEK re-grant.
//
// This is the terminal step of the org archive-key admin quorum (Shamir N-of-M
// break-glass) flow: the org archive private key is Shamir-split across M admin
// devices (archive_quorum_split.go) and reconstructed only inside the
// coordinator's Keeper during a recovery session (archive_quorum_session.go).
// Here the reconstructed key unwraps an OLD Group DEK and re-grants it to the
// current members.
//
// Key-material discipline: no reconstructed private key, raw share, or raw
// Group DEK is ever in a response — the same raw-free discipline as the other
// admin composite actions. Reconstructed material lives only in memguard
// buffers or byte slices wiped (secure.Zeroize) before returning; the response
// carries only the new per-recipient wraps.

package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

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
