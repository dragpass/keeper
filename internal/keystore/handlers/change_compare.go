// change_compare.go — the server-signed comparison decision (lv83 H1).
//
// A tracked encrypt compares a value against an entry's previous record only
// under an API-signed decision (lv79 online decision pattern):
//
//	prepare: a live labeled non-audit handle for exactly that org, group and
//	  version with a grant digest, the signed-in binding and the device; a
//	  one-use challenge bound to the handle, the entry and the exact record.
//	(online, outside Keeper's request lock) the Extension asks the API, which
//	  checks the current Group display authority (PermDecrypt), edit
//	  authority on the item and that the record is the item's current one.
//	tracked encrypt: verifies the signature and every binding, rechecks the
//	  live binding, consumes the challenge, and only then compares.
//
// Without a valid decision the verdict is "unknown", and the token and the
// next record are still sealed, so a caller without decrypt authority learns
// nothing about the value and the user's encryption is never blocked.

package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/dragpass/keeper/internal/keystore/changetrack"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

var errChangeCompareDenied = errors.New("change compare decision denied")

func recordDigestOf(rec changetrack.Sealed) [32]byte {
	return proto.ChangeRecordDigest(rec.IV, rec.Ciphertext, rec.DekVersion, rec.Seq)
}

// HandleGroupChangeComparePrepare binds one comparison to the current local
// account and device. It opens nothing.
func HandleGroupChangeComparePrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	unavailable := errs.CodeResponse(errs.ErrCodeNotFound, "change compare unavailable")
	if len(payload) > proto.GroupChangeComparePrepareMaxRequestBytes {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid change compare request")
	}
	var req proto.GroupChangeComparePrepareRequest
	if err := strictDecodeJSON(payload, &req); err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid change compare request")
	}
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.Store == nil || d.GroupSessions == nil || d.ChangeCompareChallenges == nil {
		return unavailable
	}
	label, err := d.GroupSessions.LabelOf(req.GroupHandle)
	if err != nil || !baselineLabelMatches(label, req.OrgID, req.GroupID, req.DekVersion) {
		return unavailable
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "account binding unavailable")
	}
	if !found || binding.SignedOut || binding.AccountID == "" || binding.Generation == 0 {
		return unavailable
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "device binding unavailable")
	}
	if !found || deviceID == "" {
		return unavailable
	}
	prev, _ := previousSealed(&req.PreviousRecord)
	recordDigest := recordDigestOf(prev)
	var challenge [32]byte
	if err := d.FillRandom(challenge[:]); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "change compare preparation unavailable")
	}
	handle, _ := base64.StdEncoding.DecodeString(req.GroupHandle) // Validate checked 32 bytes.
	opDigest := proto.ChangeCompareOperationDigest(challenge, handle, req.EntryID, recordDigest)
	nanos, _ := strconv.ParseInt(req.SessionIssuedAtNanos, 10, 64) // Validate checked the canonical int64.
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	context := groupDisplayContext{
		groupHandle: req.GroupHandle, accountID: binding.AccountID, deviceID: deviceID,
		tokenID: req.TokenID, sessionStartNanos: nanos,
		bindingGeneration: binding.Generation, operationDigest: opDigest,
	}
	if err := d.ChangeCompareChallenges.Put(challengeText, context, d.Now()); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "change compare preparation unavailable")
	}
	return proto.BaseResponse{Success: true, Data: proto.GroupChangeComparePrepareResponseData{
		Challenge: challengeText, GroupID: label.GroupID, DekVersion: label.DekVersion,
		GrantDigest:     hex.EncodeToString(label.GrantDigest[:]),
		RecordDigest:    hex.EncodeToString(recordDigest[:]),
		OperationDigest: hex.EncodeToString(opDigest[:]),
	}}
}

// verifyAndConsumeCompareDecision checks the decision a tracked encrypt
// carries against its own handle, entry and previous record and the live
// binding, and consumes the challenge. Dispatch holds the request lock.
func verifyAndConsumeCompareDecision(d Deps, req proto.GroupEncryptBoundTrackedRequest, prev changetrack.Sealed) error {
	dec := req.CompareDecision
	if dec == nil || d.ChangeCompareChallenges == nil || d.GroupSessions == nil || d.ServerKeyVerifier == nil || d.Store == nil {
		return errChangeCompareDenied
	}
	if dec.Validate() != nil {
		return errChangeCompareDenied
	}
	now := d.Now()
	if dec.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= dec.ExpiresAt {
		return errChangeCompareDenied
	}
	recordDigest := recordDigestOf(prev)
	if dec.RecordDigest != hex.EncodeToString(recordDigest[:]) || dec.EntryID != req.EntryID ||
		dec.OrgID != req.OrgID || dec.GroupID != req.GroupID || dec.DekVersion != req.DekVersion {
		return errChangeCompareDenied
	}
	challenge, err := base64.RawURLEncoding.DecodeString(dec.Challenge)
	if err != nil || len(challenge) != 32 {
		return errChangeCompareDenied
	}
	handle, err := base64.StdEncoding.DecodeString(req.GroupHandle)
	if err != nil {
		return errChangeCompareDenied
	}
	var c [32]byte
	copy(c[:], challenge)
	opDigest := proto.ChangeCompareOperationDigest(c, handle, req.EntryID, recordDigest)
	if dec.OperationDigest != hex.EncodeToString(opDigest[:]) {
		return errChangeCompareDenied
	}
	context, ok := d.ChangeCompareChallenges.Peek(dec.Challenge, now)
	if !ok || context.groupHandle != req.GroupHandle || context.accountID != dec.AccountID ||
		context.deviceID != dec.DeviceID || context.tokenID != dec.TokenID ||
		context.sessionStartNanos != dec.SessionIssuedAtNanos || context.operationDigest != opDigest {
		return errChangeCompareDenied
	}
	label, err := d.GroupSessions.LabelOf(req.GroupHandle)
	if err != nil || !baselineLabelMatches(label, dec.OrgID, dec.GroupID, dec.DekVersion) ||
		hex.EncodeToString(label.GrantDigest[:]) != dec.GrantDigest {
		return errChangeCompareDenied
	}
	if err := d.ServerKeyVerifier.Verify(proto.ChangeCompareDecisionCanonical(*dec), dec.Signature, dec.ServerKeyVersion); err != nil {
		return errChangeCompareDenied
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != context.accountID ||
		binding.Generation == 0 || binding.Generation != context.bindingGeneration {
		return errChangeCompareDenied
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || deviceID != context.deviceID {
		return errChangeCompareDenied
	}
	finalNow := d.Now()
	if finalNow.Unix() >= dec.ExpiresAt {
		return errChangeCompareDenied
	}
	consumed, ok := d.ChangeCompareChallenges.Consume(dec.Challenge, finalNow)
	if !ok || consumed != context {
		return errChangeCompareDenied
	}
	return nil
}
