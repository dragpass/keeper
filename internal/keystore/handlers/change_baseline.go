// change_baseline.go — the Group change-baseline actions (lv83).
//
// A baseline turns an existing bound token into the entry's first comparison
// record. It opens the token, so it carries the checks every protected open
// carries (lv79 online decision pattern):
//
//	prepare: admit only an unexpired bound token (no legacy, no expired);
//	  a live non-audit labeled handle for that org, group and version with a
//	  grant digest; a signed-in account binding and a device id; mint a
//	  one-use challenge bound to the exact token, AAD, ciphertext and entry.
//	(online, outside Keeper's request lock) the Extension asks the API for a
//	  signed decision with its own session and device signature.
//	execute: under the request lock, match the decision to the prepared
//	  operation, verify the server signature and the live binding, consume the
//	  challenge, recheck both expiries, then open the token and seal record 1.
//
// The response is the sealed record and the verdict "baseline": no plaintext,
// DEK, comparison key or tag. A refusal returns nothing. See docs/protocol.md
// "Entry value-change tracking".

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/dragpass/keeper/internal/keystore/changetrack"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// HandleGroupChangeBaselinePrepare binds one baseline attempt to the current
// local account and device. It never opens a DEK or a token.
func HandleGroupChangeBaselinePrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	if len(payload) > proto.GroupChangeBaselinePrepareMaxRequestBytes {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid change baseline request")
	}
	var req proto.GroupChangeBaselinePrepareRequest
	if err := strictDecodeJSON(payload, &req); err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid change baseline request")
	}
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	expiry, resp, ok := admitDisplayToken(d, req.TokenExpiry, "change baseline prepare")
	if !ok {
		return resp
	}
	unavailable := errs.CodeResponse(errs.ErrCodeNotFound, "change baseline unavailable")
	if d.Store == nil || d.GroupSessions == nil || d.ChangeBaselineChallenges == nil {
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
	var challenge [32]byte
	if err := d.FillRandom(challenge[:]); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "change baseline preparation unavailable")
	}
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	opDigest := baselineOperationDigest(req, challenge, expiry)
	sessionStartNanos, _ := strconv.ParseInt(req.SessionIssuedAtNanos, 10, 64) // Validate checked the canonical int64.
	context := groupDisplayContext{
		groupHandle: req.GroupHandle, accountID: binding.AccountID, deviceID: deviceID,
		tokenID: req.TokenID, sessionStartNanos: sessionStartNanos,
		bindingGeneration: binding.Generation, operationDigest: opDigest,
	}
	if err := d.ChangeBaselineChallenges.Put(challengeText, context, d.Now()); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "change baseline preparation unavailable")
	}
	fingerprint := sha256.Sum256([]byte(req.Token))
	return proto.BaseResponse{Success: true, Data: proto.GroupChangeBaselinePrepareResponseData{
		Challenge: challengeText, GroupID: label.GroupID, DekVersion: label.DekVersion,
		GrantDigest:      hex.EncodeToString(label.GrantDigest[:]),
		OperationDigest:  hex.EncodeToString(opDigest[:]),
		TokenFingerprint: hex.EncodeToString(fingerprint[:]),
	}}
}

// baselineLabelMatches requires a live, labeled, non-audit handle for exactly
// the token's org, group and version, opened from a wrapped grant.
func baselineLabelMatches(label sessions.Label, orgID, groupID string, dekVersion int) bool {
	return label.OrgID != "" && label.GroupID != "" && label.DekVersion > 0 &&
		label.OrgID == orgID && label.GroupID == groupID && label.DekVersion == dekVersion &&
		label.GrantDigest != [sha256.Size]byte{} &&
		(label.GrantPolicy == proto.GrantPolicyLegacy || label.GrantPolicy == proto.GrantPolicyDecryptOnlyV1)
}

// baselineOperationDigest commits to the exact token, the Keeper-built token
// AAD, the ciphertext, the handle, the challenge and the entry.
func baselineOperationDigest(req proto.GroupChangeBaselinePrepareRequest, challenge [32]byte, expiry proto.TokenExpiry) [32]byte {
	handle, _ := base64.StdEncoding.DecodeString(req.GroupHandle) // Validate checked 32 bytes.
	iv, _ := base64.StdEncoding.DecodeString(req.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(req.CiphertextB64)
	op := proto.ChangeBaselineOperation{
		Challenge: challenge, Token: []byte(req.Token), Ciphertext: ciphertext, EntryID: req.EntryID,
		TokenAAD: []byte(proto.BoundGroupTokenAAD(req.OrgID, req.GroupID, req.DekVersion, "", expiry)),
	}
	copy(op.GroupHandle[:], handle)
	copy(op.IV[:], iv)
	return proto.ChangeBaselineOperationDigest(op)
}

var errChangeBaselineDenied = errors.New("change baseline decision denied")

// HandleGroupChangeBaselineExecute consumes one current server decision and
// seals the entry's first comparison record from the prepared token. Dispatch
// holds requestMu across verification and the open; this handler never waits
// online.
func HandleGroupChangeBaselineExecute(d Deps, payload json.RawMessage) proto.BaseResponse {
	deny := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "change baseline unavailable")
	}
	if len(payload) > proto.GroupChangeBaselineExecuteMaxRequestBytes {
		return deny()
	}
	var req proto.GroupChangeBaselineExecuteRequest
	if err := strictDecodeJSON(payload, &req); err != nil {
		return deny()
	}
	if err := req.Validate(); err != nil {
		return deny()
	}
	p, dec := req.Prepare, req.Decision
	expiry, _, ok := admitDisplayToken(d, p.TokenExpiry, "change baseline execute")
	if !ok {
		return deny()
	}
	challenge, err := base64.RawURLEncoding.DecodeString(dec.Challenge)
	if err != nil || len(challenge) != 32 {
		return deny()
	}
	var c [32]byte
	copy(c[:], challenge)
	opDigest := baselineOperationDigest(p, c, expiry)
	fingerprint := sha256.Sum256([]byte(p.Token))
	if dec.OperationDigest != hex.EncodeToString(opDigest[:]) ||
		dec.TokenFingerprint != hex.EncodeToString(fingerprint[:]) ||
		dec.EntryID != p.EntryID || dec.OrgID != p.OrgID || dec.GroupID != p.GroupID ||
		dec.DekVersion != p.DekVersion || dec.TokenID != p.TokenID ||
		p.SessionIssuedAtNanos != strconv.FormatInt(dec.SessionIssuedAtNanos, 10) {
		return deny()
	}
	if err := verifyAndConsumeChangeBaselineDecision(d, dec, p.GroupHandle, opDigest); err != nil {
		return deny()
	}
	iv, _ := base64.StdEncoding.DecodeString(p.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(p.CiphertextB64)
	aad := []byte(proto.BoundGroupTokenAAD(p.OrgID, p.GroupID, p.DekVersion, "", expiry))
	scope := changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: p.OrgID, GroupID: p.GroupID, EntryID: p.EntryID}
	var record changetrack.Sealed
	useErr := d.GroupSessions.UseLabeled(p.GroupHandle, func(groupDEK []byte, label sessions.Label) error {
		if d.Now().Unix() >= dec.ExpiresAt || expiry.ExpiredAt(d.Now().Unix()) ||
			!baselineLabelMatches(label, p.OrgID, p.GroupID, p.DekVersion) {
			return errChangeBaselineDenied
		}
		plaintext, err := crypto.OpenAESGCM(groupDEK, iv, ciphertext, aad)
		if err != nil {
			return err
		}
		defer secure.Zeroize(plaintext)
		_, record, err = changetrack.Observe(d.Random(), scope, changetrack.Current{DEK: groupDEK, DekVersion: p.DekVersion}, nil, plaintext)
		return err
	})
	if useErr != nil || d.Now().Unix() >= dec.ExpiresAt || expiry.ExpiredAt(d.Now().Unix()) {
		return deny()
	}
	return proto.BaseResponse{Success: true, Data: proto.GroupChangeBaselineExecuteResponseData{
		ChangeVerdict: string(changetrack.VerdictBaseline),
		ChangeRecord:  changeRecordData(record),
	}}
}

// verifyAndConsumeChangeBaselineDecision checks one API-signed decision
// against Keeper's exact pending baseline and live local binding, and consumes
// its challenge. The caller holds the request lock through the open.
func verifyAndConsumeChangeBaselineDecision(d Deps, dec proto.ChangeBaselineDecision, handle string, opDigest [32]byte) error {
	if d.ChangeBaselineChallenges == nil || d.GroupSessions == nil || d.ServerKeyVerifier == nil || d.Store == nil {
		return errChangeBaselineDenied
	}
	now := d.Now()
	if dec.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= dec.ExpiresAt {
		return errChangeBaselineDenied
	}
	context, ok := d.ChangeBaselineChallenges.Peek(dec.Challenge, now)
	if !ok || context.groupHandle != handle || context.accountID != dec.AccountID ||
		context.deviceID != dec.DeviceID || context.tokenID != dec.TokenID ||
		context.sessionStartNanos != dec.SessionIssuedAtNanos || context.operationDigest != opDigest {
		return errChangeBaselineDenied
	}
	label, err := d.GroupSessions.LabelOf(handle)
	if err != nil || !baselineLabelMatches(label, dec.OrgID, dec.GroupID, dec.DekVersion) ||
		hex.EncodeToString(label.GrantDigest[:]) != dec.GrantDigest {
		return errChangeBaselineDenied
	}
	if err := d.ServerKeyVerifier.Verify(proto.ChangeBaselineDecisionCanonical(dec), dec.Signature, dec.ServerKeyVersion); err != nil {
		return errChangeBaselineDenied
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != context.accountID ||
		binding.Generation == 0 || binding.Generation != context.bindingGeneration {
		return errChangeBaselineDenied
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || deviceID != context.deviceID {
		return errChangeBaselineDenied
	}
	finalNow := d.Now()
	if finalNow.Unix() >= dec.ExpiresAt {
		return errChangeBaselineDenied
	}
	consumed, ok := d.ChangeBaselineChallenges.Consume(dec.Challenge, finalNow)
	if !ok || consumed != context {
		return errChangeBaselineDenied
	}
	return nil
}
