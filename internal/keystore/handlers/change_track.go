// change_track.go — tracked bound encrypt (lv83).
//
// One call seals the bound drag token and the entry's next comparison record
// from the same plaintext, so the two cannot describe different values. The
// comparison is a by-product: a record that cannot be verified gives the
// verdict "unknown" and never blocks or alters the token the user asked for.
// See docs/protocol.md "Entry value-change tracking".

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/changetrack"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

func changeRecordData(rec changetrack.Sealed) proto.ChangeRecord {
	return proto.ChangeRecord{
		IVB64:         base64.StdEncoding.EncodeToString(rec.IV),
		CiphertextB64: base64.StdEncoding.EncodeToString(rec.Ciphertext),
		DekVersion:    rec.DekVersion,
		Seq:           rec.Seq,
	}
}

// previousSealed decodes a supplied record. Bytes that do not decode stay
// empty and compare as unknown; the sequence still advances.
func previousSealed(r *proto.ChangeRecord) (changetrack.Sealed, bool) {
	if r == nil {
		return changetrack.Sealed{}, false
	}
	iv, _ := base64.StdEncoding.DecodeString(r.IVB64)
	ct, _ := base64.StdEncoding.DecodeString(r.CiphertextB64)
	return changetrack.Sealed{IV: iv, Ciphertext: ct, DekVersion: r.DekVersion, Seq: r.Seq}, true
}

// HandleGroupEncryptBoundTracked seals a Group bound token and its change
// record under the DEK behind group_handle.
func HandleGroupEncryptBoundTracked(d Deps, req proto.GroupEncryptBoundTrackedRequest) proto.BaseResponse {
	const action = "group encrypt bound tracked"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	tc := req.TokenContext()
	expiry, resp, ok := boundExpiry(d, tc.TokenExpiry, action)
	if !ok {
		return resp
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64")
	}
	defer secure.Zeroize(plaintext)
	scope := changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: req.OrgID, GroupID: req.GroupID, EntryID: req.EntryID}
	aad := []byte(proto.BoundGroupTokenAAD(tc.OrgID, tc.GroupID, tc.DekVersion, "", expiry))

	prev, hasPrev := previousSealed(req.PreviousRecord)
	crossVersion := hasPrev && prev.DekVersion != tc.DekVersion
	// A previous record under another DEK version is classified first, under
	// its own handle; the session store does not allow two handles at once.
	var verdict changetrack.Verdict
	var seq uint64
	if crossVersion {
		v, n, err := classifyUnderPreviousHandle(d, req, scope, prev, plaintext)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeValidation, "change record sequence exhausted")
		}
		verdict, seq = v, n
	}

	var iv, ciphertext []byte
	var record changetrack.Sealed
	useErr := d.GroupSessions.UseLabeled(tc.GroupHandle, func(groupDEK []byte, label sessions.Label) error {
		if err := checkBoundLabel(label, tc); err != nil {
			return err
		}
		if isDecryptOnlyLabel(label) {
			return errHandleDecryptOnly
		}
		if !crossVersion {
			var p *changetrack.Sealed
			if hasPrev {
				p = &prev
			}
			v, n, err := changetrack.Next(scope, p, groupDEK, plaintext)
			if err != nil {
				return errors.New("change record failed")
			}
			verdict, seq = v, n
		}
		rec, err := changetrack.Seal(d.Random(), groupDEK, scope, tc.DekVersion, seq, plaintext)
		if err != nil {
			return errors.New("change record failed")
		}
		i, c, err := crypto.SealAESGCM(d.Random(), groupDEK, plaintext, aad)
		if err != nil {
			return errors.New("encrypt failed")
		}
		iv, ciphertext, record = i, c, rec
		return nil
	})
	if useErr != nil {
		return boundSessionError(useErr, action)
	}
	d.Logger.Println(action + " successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptBoundTrackedResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		ChangeVerdict: string(verdict),
		ChangeRecord:  changeRecordData(record),
	}}
}

// classifyUnderPreviousHandle compares plaintext with a record sealed under
// another DEK version. A missing, expired, audit-only or mismatched handle
// leaves the verdict unknown: the comparison never blocks the encryption.
func classifyUnderPreviousHandle(d Deps, req proto.GroupEncryptBoundTrackedRequest, scope changetrack.Scope, prev changetrack.Sealed, plaintext []byte) (changetrack.Verdict, uint64, error) {
	verdict, seq, err := changetrack.Next(scope, &prev, nil, plaintext)
	if err != nil || req.PreviousGroupHandle == "" {
		return verdict, seq, err
	}
	_ = d.GroupSessions.UseLabeled(req.PreviousGroupHandle, func(prevDEK []byte, label sessions.Label) error {
		if isAuditOnlyLabel(label) {
			return nil
		}
		if label.OrgID != "" && label.OrgID != req.OrgID {
			return nil
		}
		if label.GroupID != "" && (label.GroupID != req.GroupID || label.DekVersion != prev.DekVersion) {
			return nil
		}
		verdict, seq, err = changetrack.Next(scope, &prev, prevDEK, plaintext)
		return nil
	})
	return verdict, seq, err
}

// HandleDEKUnwrapAndEncryptBoundTracked seals a personal bound token and its
// change record under the device-wrapped personal DEK. The scope is this
// device's signed-in account binding.
func HandleDEKUnwrapAndEncryptBoundTracked(d Deps, req proto.DEKUnwrapAndEncryptBoundTrackedRequest) proto.BaseResponse {
	const action = "dek unwrap and encrypt bound tracked"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	expiry, resp, ok := boundExpiry(d, req.TokenExpiry, action)
	if !ok {
		return resp
	}
	accountID, resp, ok := boundAccountID(d, action)
	if !ok {
		return resp
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64")
	}
	defer secure.Zeroize(plaintext)
	scope := changetrack.Scope{Kind: changetrack.ScopePersonal, ScopeID: accountID, EntryID: req.EntryID}
	aad := []byte(proto.BoundPersonalTokenAAD(accountID, proto.BoundPersonalDekVersion, expiry))
	return withPersonalDEK(d, req.EncryptedDEKB64, func(dek []byte) proto.BaseResponse {
		var prev *changetrack.Previous
		if p, ok := previousSealed(req.PreviousRecord); ok {
			prev = &changetrack.Previous{Record: p, DEK: dek}
		}
		verdict, record, err := changetrack.Observe(d.Random(), scope,
			changetrack.Current{DEK: dek, DekVersion: proto.BoundPersonalDekVersion}, prev, plaintext)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "change record failed")
		}
		iv, ciphertext, err := crypto.SealAESGCM(d.Random(), dek, plaintext, aad)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "encrypt failed")
		}
		d.Logger.Println(action + " successful")
		return proto.BaseResponse{Success: true, Data: proto.DEKUnwrapAndEncryptBoundTrackedResponseData{
			IVB64:         base64.StdEncoding.EncodeToString(iv),
			CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
			ChangeVerdict: string(verdict),
			ChangeRecord:  changeRecordData(record),
		}}
	})
}
