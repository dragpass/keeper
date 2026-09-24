// mls_leaf_handover.go — the old device's approval of a takeover (0.0.55,
// design §0.3 policy 1, Q1), and the conversion of a relayed handover into the
// statement the succession rule reads (chatstate/succession.go).

package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// handoverSignClockSkewSeconds is how far past the full window a relayed
// expires_at may lie before it reads as a request issued in the future.
const handoverSignClockSkewSeconds = 60

// HandleMLSLeafHandoverSign signs this device's approval of new_declaration
// taking its seat in every group of the account.
//
// What it checks before signing, all against what this device holds:
//
//   - this device has a usable active leaf, for account_id. That leaf is the
//     one every group tree holds for this account, and its key signs.
//   - new_declaration is a rotate for account_id, for another device, whose
//     signature verifies under the account public key this device holds. A
//     server that swaps in a declaration of another account key, or of this
//     very device, gets nothing signed.
//   - the declaration has not ended, and the request window has not closed:
//     now < expires_at <= now + 600 + skew.
//
// The app calls this only once a person on this device has approved the
// request it shows, with the comparison code both devices display. That
// person is the approval policy 1 asks for; this action is the proof of it.
func HandleMLSLeafHandoverSign(d Deps, req proto.MLSLeafHandoverSignRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	refuse := func(message string) proto.BaseResponse {
		d.Logger.Printf("mls leaf handover sign refused: %s", message)
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeHandoverInvalid), message)
	}
	now := d.Now().Unix()
	if req.ExpiresAt <= now || req.ExpiresAt > now+proto.MLSLeafHandoverMaxSeconds+handoverSignClockSkewSeconds {
		return refuse("the takeover request's window has closed or is not a window this device would approve")
	}
	decl := req.NewDeclaration
	if decl.AccountID != req.AccountID || decl.Reason != proto.MLSLeafReasonRotate || decl.NotAfter <= now {
		return refuse("the new declaration is not a current rotate for this account")
	}
	accountPEM, err := keychain.GetPublicKey(d.Store)
	if err != nil || accountPEM == "" {
		return errs.CodeResponse(errs.ErrCodeNotFound, "account public key not found (signup required first)")
	}
	accountKey, err := crypto.ParsePublicKey(accountPEM)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "account public key is unreadable")
	}
	if err := VerifyLeafDeclaration(decl, accountKey); err != nil {
		return refuse("the new declaration is not signed by this account's key")
	}

	var resp proto.BaseResponse
	lockErr := keychain.WithMLSLeafLock(d.Store, func() error {
		active, pending, failure, ok := loadMLSLeafSlots(d)
		if !ok {
			resp = failure
			return nil
		}
		defer wipeMLSLeafSlots(active, pending)
		if active == nil || !active.Usable() || active.AccountID != req.AccountID {
			resp = errs.CodeResponse(errs.ErrCodeNotFound, "this device holds no active mls leaf for the account")
			return nil
		}
		if active.DeviceID == decl.DeviceID {
			resp = refuse("the new declaration is for this device itself")
			return nil
		}
		resp = signHandover(active, decl, now, req.ExpiresAt)
		return nil
	})
	if lockErr != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "mls leaf lock could not be acquired")
	}
	if resp.Success {
		d.Logger.Println("mls leaf handover sign successful")
	}
	return resp
}

func signHandover(active *keychain.MLSLeafKey, decl proto.MLSLeafDeclaration, now, expiresAt int64) proto.BaseResponse {
	oldFingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(active.PublicKey)
	if err != nil || len(active.SecretKey) != ed25519.PrivateKeySize {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "the active mls leaf key is unreadable")
	}
	h := chatstate.LeafHandover{
		AccountID:      decl.AccountID,
		OldDeviceID:    active.DeviceID,
		OldFingerprint: oldFingerprint,
		NewDeviceID:    decl.DeviceID,
		NewFingerprint: decl.SignatureKeyFingerprint,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
	}
	h.Signature = ed25519.Sign(ed25519.PrivateKey(active.SecretKey), []byte(chatstate.LeafHandoverCanonical(h)))
	if err := h.VerifyUnder(active.PublicKey); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "the handover did not verify under the key that signed it")
	}
	return proto.BaseResponse{Success: true, Data: proto.MLSLeafHandoverSignResponseData{Handover: handoverWire(h)}}
}

func handoverWire(h chatstate.LeafHandover) proto.MLSLeafHandover {
	return proto.MLSLeafHandover{
		AccountID:         h.AccountID,
		OldDeviceID:       h.OldDeviceID,
		OldSignatureKeyFP: h.OldFingerprint,
		NewDeviceID:       h.NewDeviceID,
		NewSignatureKeyFP: h.NewFingerprint,
		IssuedAt:          h.IssuedAt,
		ExpiresAt:         h.ExpiresAt,
		Signature:         base64.StdEncoding.EncodeToString(h.Signature),
	}
}

var errHandoverSignature = errors.New("handover signature is not valid standard Base64")

// handoverFromWire reads a relayed handover. Validate has already bounded it.
func handoverFromWire(w proto.MLSLeafHandover) (chatstate.LeafHandover, error) {
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return chatstate.LeafHandover{}, errHandoverSignature
	}
	return chatstate.LeafHandover{
		AccountID:      w.AccountID,
		OldDeviceID:    w.OldDeviceID,
		OldFingerprint: w.OldSignatureKeyFP,
		NewDeviceID:    w.NewDeviceID,
		NewFingerprint: w.NewSignatureKeyFP,
		IssuedAt:       w.IssuedAt,
		ExpiresAt:      w.ExpiresAt,
		Signature:      sig,
	}, nil
}
