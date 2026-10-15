// group_audit.go — the two drag actions for an audit-only Group DEK version:
// group_encrypt_audit and group_decrypt_audit_to_clipboard.
//
// Each runs the same checks in the same order before any key is used:
//
//	size cap → strict decode (no unknown / duplicate / missing field)
//	  → structural validation
//	  → the handle was opened from an audit-only grant for exactly this org,
//	    group and version
//	  → the receipt / permit names the same table, org, group, version and the
//	    SHA-256 of the table bytes the caller sent
//	  → its account_id is the account this device's binding records, signed in
//	  → its window holds (issued_at <= now+5, now < expires_at, fixed span)
//	  → the server signature verifies under the named key version
//	  → it is consumed, once, in this process
//	  → the token key is derived: HKDF-SHA256(ikm = Group DEK,
//	    salt = SHA-256(table), info = the audit AAD), and the token is sealed or
//	    opened under it with the same AAD.
//
// The AAD and the derived key are built here from validated fields; the
// caller never supplies either. A token sealed with the raw Group DEK (the
// legacy drag actions, group_encrypt_with_aad) does not open here, and a token
// sealed here does not open anywhere else.

package handlers

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// auditClockSkewSeconds — how far into the future issued_at may sit.
const auditClockSkewSeconds = 5

// auditConsumedRetention keeps a consumed key past its own expiry, so a wall
// clock stepped back a few minutes cannot revive a spent authorization.
const auditConsumedRetention = 5 * time.Minute

// deriveAuditTokenKey is the per-token key of an audit-only drag token.
func deriveAuditTokenKey(groupDEK, table []byte, aad string) ([]byte, error) {
	salt := sha256.Sum256(table)
	return hkdf.Key(sha256.New, groupDEK, salt[:], aad, 32)
}

// HandleGroupEncryptAudit seals one drag token under an audit-only version.
func HandleGroupEncryptAudit(d Deps, payload json.RawMessage) proto.BaseResponse {
	d.Logger.Println("group encrypt audit request processing...")
	var req proto.GroupEncryptAuditRequest
	if resp, ok := decodeAuditRequest(payload, &req); !ok {
		return resp
	}
	tc := req.TokenContext()
	table, resp, ok := auditPreflight(d, tc)
	if !ok {
		return resp
	}
	r := req.Receipt
	tableSum := sha256.Sum256(table)
	bound := r.TableID == tc.TableID && r.OrgID == tc.OrgID && r.GroupID == tc.GroupID &&
		r.DekVersion == tc.DekVersion && r.TableSHA256 == hex.EncodeToString(tableSum[:])
	if !bound {
		return auditNotAuthorized(d, "receipt binding")
	}
	if resp, ok := auditAccountMatches(d, r.AccountID); !ok {
		return resp
	}
	if resp, ok := auditAuthorize(d, r.IssuedAt, r.ExpiresAt, proto.AuditTableReceiptTTLSeconds,
		proto.AuditTableReceiptCanonical(r), r.Signature, r.ServerKeyVersion, "receipt|"+r.TableID); !ok {
		return resp
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return auditInvalidInput("plaintext_b64 must be standard Base64")
	}
	defer secure.Zeroize(plaintext)

	aad := proto.AuditDragAADCanonical(tc.OrgID, tc.GroupID, tc.DekVersion, tc.TableID)
	var iv, ciphertext []byte
	useErr := d.GroupSessions.Use(tc.GroupHandle, func(groupDEK []byte) error {
		key, err := deriveAuditTokenKey(groupDEK, table, aad)
		if err != nil {
			return err
		}
		defer secure.Zeroize(key)
		iv, ciphertext, err = crypto.SealAESGCM(d.Random(), key, plaintext, []byte(aad))
		return err
	})
	if useErr != nil {
		return auditSessionError(d, useErr)
	}
	d.Logger.Println("group encrypt audit successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}

// HandleGroupDecryptAuditToClipboard opens one audit token into the clipboard.
func HandleGroupDecryptAuditToClipboard(d Deps, payload json.RawMessage) proto.BaseResponse {
	d.Logger.Println("group decrypt audit to clipboard request processing...")
	var req proto.GroupDecryptAuditToClipboardRequest
	if resp, ok := decodeAuditRequest(payload, &req); !ok {
		return resp
	}
	plaintext, resp, ok := openAuditToken(d, req.TokenContext(), req.Permit, req.IVB64, req.CiphertextB64)
	if !ok {
		return resp
	}
	return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, "group decrypt audit to clipboard")
}

// openAuditToken runs the permit checks, consumes the permit and opens the
// token. The caller zeroizes the plaintext.
func openAuditToken(
	d Deps, tc proto.AuditTokenContext, p proto.AuditDecryptPermit, ivB64, ciphertextB64 string,
) ([]byte, proto.BaseResponse, bool) {
	table, resp, ok := auditPreflight(d, tc)
	if !ok {
		return nil, resp, false
	}
	tableSum := sha256.Sum256(table)
	bound := p.TableID == tc.TableID && p.OrgID == tc.OrgID && p.GroupID == tc.GroupID &&
		p.DekVersion == tc.DekVersion && p.TableSHA256 == hex.EncodeToString(tableSum[:])
	if !bound {
		return nil, auditNotAuthorized(d, "permit binding"), false
	}
	if resp, ok := auditAccountMatches(d, p.AccountID); !ok {
		return nil, resp, false
	}
	if resp, ok := auditAuthorize(d, p.IssuedAt, p.ExpiresAt, proto.AuditDecryptPermitTTLSeconds,
		proto.AuditDecryptPermitCanonical(p), p.Signature, p.ServerKeyVersion, "permit|"+p.PermitID); !ok {
		return nil, resp, false
	}
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, auditInvalidInput("iv_b64 must be standard Base64"), false
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, auditInvalidInput("ciphertext_b64 must be standard Base64"), false
	}

	aad := proto.AuditDragAADCanonical(tc.OrgID, tc.GroupID, tc.DekVersion, tc.TableID)
	var plaintext []byte
	var openErr error
	useErr := d.GroupSessions.Use(tc.GroupHandle, func(groupDEK []byte) error {
		key, err := deriveAuditTokenKey(groupDEK, table, aad)
		if err != nil {
			return err
		}
		defer secure.Zeroize(key)
		plaintext, openErr = crypto.OpenAESGCM(key, iv, ciphertext, []byte(aad))
		return nil
	})
	if useErr != nil {
		return nil, auditSessionError(d, useErr), false
	}
	if openErr != nil {
		d.Logger.Println("group audit decrypt failed (gcm)")
		return nil, errs.CodeResponse(errs.ErrorCode(proto.AuditDecryptFailed), "audit token decrypt failed"), false
	}
	return plaintext, proto.BaseResponse{}, true
}

// auditPreflight checks the handle's policy and context against the request
// and decodes the table. It spends nothing.
func auditPreflight(d Deps, tc proto.AuditTokenContext) ([]byte, proto.BaseResponse, bool) {
	label, err := d.GroupSessions.LabelOf(tc.GroupHandle)
	if err != nil {
		return nil, sessionUseError(err, "group audit"), false
	}
	want := sessions.Label{
		OrgID:       tc.OrgID,
		GrantPolicy: proto.GrantPolicyAuditOnlyV1,
		GroupID:     tc.GroupID,
		DekVersion:  tc.DekVersion,
	}
	if label != want {
		d.Logger.Println("group audit refused: the handle is not an audit-only handle for this org, group and version")
		return nil, errs.CodeResponse(errs.ErrorCode(proto.GroupPolicyNotAuditOnly),
			"the group handle was not opened from the audit-only grant of this org, group and version"), false
	}
	table, err := base64.StdEncoding.DecodeString(tc.TableB64)
	if err != nil || len(table) != proto.AuditShuffleTableBytes {
		return nil, auditInvalidInput("table_b64 must be 256 bytes of standard Base64"), false
	}
	return table, proto.BaseResponse{}, true
}

// auditAccountMatches holds a receipt or permit to the account this device
// is signed in to, as its account binding records. It runs before anything
// is consumed. The binding is a hint any Native Messaging caller can rewrite
// (account_binding_set), so this keeps an honest device from spending
// another account's authorization (the server would log the other account
// as the reader or writer); it does not stop a tampered Extension that
// rewrites the binding first.
func auditAccountMatches(d Deps, accountID string) (proto.BaseResponse, bool) {
	binding, present, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		d.Logger.Printf("group audit: account binding unreadable: %s", deviceIdentityErrorClass(err))
		return deviceIdentityErrorResponse(err), false
	}
	if !present || binding.SignedOut || binding.AccountID == "" {
		d.Logger.Println("group audit refused: no signed-in account binding on this device")
		return errs.CodeResponse(errs.ErrorCode(proto.AuditAccountUnbound),
			"this device has no signed-in account to match the audit authorization to"), false
	}
	if binding.AccountID != accountID {
		d.Logger.Println("group audit refused: the authorization was issued to another account")
		return errs.CodeResponse(errs.ErrorCode(proto.AuditAccountMismatch),
			"the audit authorization was issued to another account"), false
	}
	return proto.BaseResponse{}, true
}

// auditAuthorize checks the window and the signature of a receipt or permit
// and consumes it. Consumption sits after the signature so a forged
// authorization cannot burn a real one, and before the key is used so a tag
// failure cannot be retried against the same authorization.
func auditAuthorize(
	d Deps, issuedAt, expiresAt, ttl int64, canonical, signature string, keyVersion uint, consumeKey string,
) (proto.BaseResponse, bool) {
	now := d.Now()
	if issuedAt > now.Unix()+auditClockSkewSeconds || now.Unix() >= expiresAt || expiresAt-issuedAt != ttl {
		return auditNotAuthorized(d, "window"), false
	}
	if err := d.ServerKeyVerifier.Verify(canonical, signature, keyVersion); err != nil {
		return auditNotAuthorized(d, "signature"), false
	}
	spent, err := d.AuditAuthorizations.Consume(consumeKey, time.Unix(expiresAt, 0).Add(auditConsumedRetention), now)
	if errors.Is(err, errAuditAuthorizationBusy) {
		return errs.CodeResponse(errs.ErrorCode(proto.AuditBusy), "audit authorization record is full"), false
	}
	if err != nil || !spent {
		return auditNotAuthorized(d, "single use"), false
	}
	return proto.BaseResponse{}, true
}

func decodeAuditRequest(payload json.RawMessage, req proto.Validator) (proto.BaseResponse, bool) {
	if len(payload) > proto.AuditMaxRequestBytes {
		return auditInvalidInput("request exceeds the maximum size"), false
	}
	if err := strictDecodeJSON(payload, req); err != nil {
		return auditInvalidInput("invalid audit request: " + err.Error()), false
	}
	if err := req.Validate(); err != nil {
		return auditInvalidInput(err.Error()), false
	}
	return proto.BaseResponse{}, true
}

func auditSessionError(d Deps, err error) proto.BaseResponse {
	d.Logger.Println("group audit: handle closed or expired after the authorization was spent")
	return sessionUseError(err, "group audit")
}

func auditInvalidInput(message string) proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(proto.AuditInvalidInput), message)
}

func auditNotAuthorized(d Deps, stage string) proto.BaseResponse {
	d.Logger.Printf("group audit not authorized (%s check)", stage)
	return errs.CodeResponse(errs.ErrorCode(proto.AuditNotAuthorized), "audit operation is not authorized")
}
