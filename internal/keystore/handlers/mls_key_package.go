// mls_key_package.go — mls_key_package_generate: single-use KeyPackages for
// this device's active leaf, with their private keys kept in the owner's pool.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.3, §12.2.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleMLSKeyPackageGenerate produces `count` KeyPackages, each carrying the
// active leaf declaration in its LeafNode extension, for the caller to upload.
//
// The gate is a purpose-bound server challenge, as for mls_leaf_declare, and
// not a conversation-state permit: a new device has no conversation to be
// permitted for, and it needs KeyPackages to be added to its first one. The
// challenge's account and device must be the ones the active leaf was declared
// for, so a challenge for one account cannot put another account's leaf into
// groups. Kept off the MCP surface.
//
// No KeyPackage outlives the declaration it embeds: each ends at the
// declaration's not_after if that comes before the usual lifetime, and the
// real value is what the response reports. A declaration that has already
// expired produces nothing; rotate first.
//
// The KeyPackages' private keys are sealed into the owner's pool before the
// response is built. A KeyPackage handed out without its keys kept is one
// nobody can ever add this device through.
//
// The response names the leaf the KeyPackages were built for by its signature
// key fingerprint. The server cannot parse a KeyPackage, so without it an
// upload would be filed under whatever declaration is live when it arrives.
//
// Everything from reading the active slot to writing the pool runs under
// keychain.WithMLSLeafLock, and the slot is read once, by NewDeviceSession.
// A promote in another process therefore lands before the read or after the
// pool write, never in between.
func HandleMLSKeyPackageGenerate(d Deps, req proto.MLSKeyPackageGenerateRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.ServerSignature, req.ServerKeyVersion, "mls key package generate"); !ok {
		return resp
	}
	if resp, ok := requirePurposeChallenge(d, req.ChallengeToken, req.AccountID, req.DeviceID,
		proto.ParseMLSKeyPackageChallenge, proto.MLSKeyPackageChallengeTTLSeconds); !ok {
		return resp
	}
	if !mls.Available() {
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeCapabilityRequired),
			"this Keeper was built without the MLS library")
	}

	var resp proto.BaseResponse
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		resp = generateKeyPackagesLocked(d, req)
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	if resp.Success {
		d.Logger.Printf("mls key package generate successful (%d key packages)",
			len(resp.Data.(proto.MLSKeyPackageGenerateResponseData).KeyPackages))
	}
	return resp
}

// generateKeyPackagesLocked is the critical section. The leaf slot is read by
// NewDeviceSession only, and chatstate touches its own slots and file locks;
// nothing here takes WithMLSLeafLock again.
func generateKeyPackagesLocked(d Deps, req proto.MLSKeyPackageGenerateRequest) proto.BaseResponse {
	session, leaf, err := mls.NewDeviceSession(d.Store)
	switch {
	case errors.Is(err, mls.ErrNoLeafKey), errors.Is(err, mls.ErrNoLeafDeclaration):
		return errs.CodeResponse(errs.ErrCodeNotFound, "no active mls leaf key; mls_leaf_declare enroll and promote first")
	case errors.Is(err, mls.ErrLeafKeyUnreadable):
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf key record is unreadable")
	case err != nil:
		d.Logger.Println("mls key package generate: the device session could not be opened")
		return errs.CodeResponse(errs.ErrCodeInternal, "mls device session could not be opened")
	}
	defer session.Close()

	if leaf.AccountID != req.AccountID || leaf.DeviceID != req.DeviceID {
		return errs.CodeResponse(errs.ErrCodeValidation, "the active mls leaf was declared for a different account or device")
	}
	ext, err := decodeMLSLeafExtension(leaf.Declaration)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "active mls leaf declaration is unreadable")
	}
	decl := ext.Declaration
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.PublicKey)
	if err != nil || fingerprint != decl.SignatureKeyFingerprint {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "active mls leaf declaration does not name the stored key")
	}
	if d.Now().Unix() >= decl.NotAfter {
		return errs.CodeResponse(errs.ErrCodeValidation, "the active mls leaf declaration has expired; rotate first")
	}

	packages, pool, err := session.KeyPackages(req.Count, uint64(decl.NotAfter))
	if err != nil {
		d.Logger.Println("mls key package generate: key package generation failed")
		return errs.CodeResponse(errs.ErrCodeInternal, "mls key package generation failed")
	}
	defer func() {
		for _, e := range pool {
			secure.Zeroize(e.Private)
		}
	}()
	// The pool records the leaf so a promote can drop exactly the entries
	// that stop being usable with it.
	for i := range pool {
		pool[i].Leaf = fingerprint
	}

	store, err := chatstate.Open(d.Store, req.AccountID)
	if err != nil {
		d.Logger.Println("mls key package generate: the chat state could not be opened")
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls key package private keys could not be stored")
	}
	defer store.Close()
	if err := store.AddKeyPackages(pool, d.Now()); err != nil {
		d.Logger.Println("mls key package generate: the key package pool could not be written")
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls key package private keys could not be stored")
	}

	out := make([]proto.MLSKeyPackage, 0, len(packages))
	for _, kp := range packages {
		out = append(out, proto.MLSKeyPackage{
			KeyPackageB64: base64.StdEncoding.EncodeToString(kp.Message),
			NotAfter:      kp.NotAfter,
		})
	}
	return proto.BaseResponse{Success: true, Data: proto.MLSKeyPackageGenerateResponseData{
		KeyPackages: out, LeafSignatureKeyFingerprint: fingerprint,
	}}
}
