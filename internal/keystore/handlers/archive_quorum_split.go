// archive_quorum_split.go — quorum share creation: split + per-admin rewrap.
//
// Part of the org archive-key admin quorum (Shamir N-of-M break-glass) flow;
// see archive_quorum_combine.go for the flow overview. This file covers the two
// steps that produce and re-target shares:
//
//   - prepareArchiveKeySplit: the durable preparation (journal, retained
//     original key) behind the signed split gate in archive_split_authority.go.
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// The serving Keeper owner serializes journal read/create so concurrent App
// retries cannot return two different sets of shares for one operation. The
// org archive key generate and the rotation actions hold it too (lv96), so
// every writer of the org archive slots runs alone. A holder never takes it
// again and never takes it while holding the keychain process lock.
var archiveSplitPreparationMu sync.Mutex

// archiveSplitBinding is the part of the verified split decision the journal
// keeps, so a retry under a fresh decision must name the same requester,
// configuration and archive key, and finalization can be checked against it.
type archiveSplitBinding struct {
	Kind                      string `json:"kind,omitempty"`
	SourceConfigDigest        string `json:"source_config_digest,omitempty"`
	TargetKeyFingerprint      string `json:"target_key_fingerprint,omitempty"`
	ActiveKeySPKIFingerprint  string `json:"active_key_spki_fingerprint,omitempty"`
	OrgID                     string `json:"org_id"`
	AccountID                 string `json:"account_id"`
	ConfigDigest              string `json:"config_digest"`
	ArchiveKeySPKIFingerprint string `json:"archive_key_spki_fingerprint"`
	SplitRequestDigest        string `json:"split_request_digest"`
}

// prepareArchiveKeySplit prepares wrapped shares while keeping the source key.
// A separate authenticated finalization must confirm server persistence before
// removing the source private key. Missing source key returns not_found. Only
// HandleArchiveKeySplit calls it, after the signed split decision passed.
func prepareArchiveKeySplit(d Deps, req proto.ArchiveKeySplitRequest, binding archiveSplitBinding, current func() bool) proto.BaseResponse {
	d.Logger.Println("archive key split processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()

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

	if binding.Kind == archiveOperationKindReconfiguration {
		var response proto.BaseResponse
		err := archiveSlotProcessLock(d.Store, func() error {
			if current == nil || !current() {
				response = denyArchiveSplit()
				return nil
			}
			slot := keychain.OrgArchiveReconfigurationSlot(req.OrgID)
			pub, err := slot.GetPublic(d.Store)
			if err != nil || fingerprintBase64Public(pub) != binding.TargetKeyFingerprint {
				response = denyArchiveSplit()
				return nil
			}
			spki, err := crypto.RewrapKeyFingerprint(pub)
			if err != nil || spki != binding.ArchiveKeySPKIFingerprint {
				response = denyArchiveSplit()
				return nil
			}
			raw, err := d.Store.Get(config.Service, archiveReconfigurationJournalAccount(req.OrgID))
			var staged archiveReconfigurationJournal
			if err != nil || json.Unmarshal([]byte(raw), &staged) != nil || staged.Finalization != "" || staged.Closure != nil || staged.UnregisteredCleanup != "" || ((staged.OwnerAccountID != "" || staged.OwnerDeviceID != "") && (staged.OwnerAccountID != binding.AccountID || staged.OwnerDeviceID != req.ReconfigurationDecision.DeviceID)) || staged.Kind != binding.Kind || staged.OrgID != req.OrgID || staged.OperationID != req.OperationID || staged.TargetKeyFingerprint != binding.TargetKeyFingerprint {
				response = denyArchiveSplit()
				return nil
			}
			response = splitArchiveSlot(d, req, binding, pubs, slot, pub)
			return nil
		})
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "archive slot lock unavailable")
		}
		return response
	}
	// The slot holding the org's public key owns its key. Once a split has
	// wiped that slot's private half, the device-wide key is another key and
	// must not be split in its place.
	slot, activePublic, found, err := keychain.FindArchiveKey(d.Store, keychain.OrgArchiveActiveCandidates(req.OrgID))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive key failed")
	}
	if !found {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive key unavailable")
	}
	return splitArchiveSlot(d, req, binding, pubs, slot, activePublic)
}

func splitArchiveSlot(d Deps, req proto.ArchiveKeySplitRequest, binding archiveSplitBinding, pubs []*rsa.PublicKey, slot keychain.ArchiveKeySlot, activePublic string) proto.BaseResponse {
	// The decision changes on every retry; the journal names the request only.
	req.Decision = nil
	req.ReconfigurationDecision = nil
	if req.Kind == "activation" {
		req.Kind = ""
	}
	requestBytes, err := json.Marshal(req)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid split request")
	}
	requestDigest := sha256.Sum256(requestBytes)
	journal, found, err := loadArchiveSplitJournal(d.Store, slot)
	if errors.Is(err, errArchiveSplitJournalInconsistent) {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive split preparation unavailable")
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive split preparation failed")
	}
	if found {
		if journal.OperationID != req.OperationID ||
			journal.RequestDigest != hex.EncodeToString(requestDigest[:]) ||
			journal.Binding != binding || journal.State != "" ||
			fingerprintBase64Public(activePublic) != journal.KeyFingerprint ||
			journal.ShareCount != len(req.RecipientPublicKeys) {
			return errs.CodeResponse(errs.ErrCodeNotFound, "archive split preparation unavailable")
		}
		result, err := readArchiveSplitResult(d.Store, slot, journal)
		if errors.Is(err, errArchiveSplitJournalInconsistent) {
			return errs.CodeResponse(errs.ErrCodeNotFound, "archive split preparation unavailable")
		}
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive split preparation failed")
		}
		return proto.BaseResponse{Success: true, Data: result}
	}
	privKeyBuf, err := getArchiveSlotPrivateKeySecure(d.Store, slot)
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
	if fingerprintBase64Public(activePublic) != keyFingerprint {
		return errs.CodeResponse(errs.ErrCodeNotFound, "archive key changed")
	}

	shares, err := crypto.SplitSecret(privKeyBuf.Bytes(), req.ThresholdN, len(pubs))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "shamir split failed: "+err.Error())
	}

	out := make([]proto.WrappedShare, len(shares))
	for i, s := range shares {
		serialized := crypto.SerializeShare(s)
		wrappedKey, ciphertext, wrapErr := crypto.HybridWrap(pubs[i], serialized)
		proofPublicKey, proofErr := archiveShareProofPublicKey(serialized, req.OperationID, int(s.X))
		secure.Zeroize(serialized)
		secure.Zeroize(s.Y)
		if wrapErr != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure,
				fmt.Sprintf("hybrid wrap share %d failed: %v", i, wrapErr))
		}
		if proofErr != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "derive share proof key failed")
		}
		out[i] = proto.WrappedShare{
			ShareIndex:           int(s.X),
			WrappedKey:           wrappedKey,
			Ciphertext:           ciphertext,
			RecipientFingerprint: fingerprintBase64Public(req.RecipientPublicKeys[i]),
			ProofPublicKey:       proofPublicKey,
		}
	}

	result := proto.ArchiveKeySplitResponseData{KeyFingerprint: keyFingerprint, Shares: out}
	if recordArchiveSplitPreparation(d.Store, slot, archiveSplitJournal{
		OperationID: req.OperationID, RequestDigest: hex.EncodeToString(requestDigest[:]),
		KeyFingerprint: keyFingerprint, Binding: binding,
	}, result) != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save archive split preparation failed")
	}
	d.Logger.Printf("archive key split prepared: %d shares (threshold %d), private key retained",
		len(out), req.ThresholdN)
	return proto.BaseResponse{Success: true, Data: result}
}

// HandleArchiveShareRewrap re-wraps an admin's own hybrid-wrapped share from
// their ACCOUNT archive key (the dedicated per-account receiving slot — the
// key published to the account directory that the share was wrapped to at
// split time) to the recovery session public key, so the coordinator can
// combine it. The share plaintext lives only briefly in Keeper memory.
func rewrapArchiveShare(d Deps, req proto.ArchiveShareRewrapRequest) proto.BaseResponse {
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
