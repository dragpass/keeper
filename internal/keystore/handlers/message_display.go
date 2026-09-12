// message_display.go — the Secure Message Overlay reveal, both halves.
//
// HandleMessageDisplayPrepare mints a challenge over a message context.
// HandleGroupDecryptWithAadForAppDisplay verifies a server-signed permit
// against that challenge and returns the plaintext.
//
// That second response is the protocol's only plaintext-returning one, so the
// interesting part of this file is everything that has to hold before the
// plaintext is produced:
//
//	strict decode (no unknown / duplicate / missing field, 16 KiB cap)
//	  → structural validation
//	  → the challenge exists in this process
//	  → the permit, the request, and the remembered challenge agree field for
//	    field, including the payload digest
//	  → the permit window holds (issued_at <= now+5, now < expires_at,
//	    expires_at - issued_at == 30)
//	  → the server signature verifies under the named key version
//	  → the message token itself has not expired
//	  → the challenge is consumed, atomically and for good
//	  → the open succeeds under an AAD the Keeper built, not one it was given
//	  → the plaintext is well-formed UTF-8 of a sane size
//	  → the token still has not expired
//
// The order is the contract (dragpass-control-plane
// docs/exec-plans/active/secure-message-overlay-implementation.md §3), not an
// implementation detail. Consumption sits where it does deliberately: after the
// permit verifies, so a caller holding a bad signature cannot burn somebody's
// challenge, and before the decrypt, so a tag failure cannot be retried against
// the same authorization.
//
// Unlike the other handlers these two take the raw payload rather than a
// decoded request. The dispatcher's shared `process` helper decodes with plain
// json.Unmarshal, which cannot refuse a duplicate key — and a duplicate key in
// a signature-bound request means verifying one value and decrypting under
// another. See strict_json.go.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// messageDisplayClockSkewSeconds — how far into the future a permit's issued_at
// may sit. Covers ordinary server/client clock drift and nothing more; the
// message token's own expiry gets no grace at all.
const messageDisplayClockSkewSeconds = 5

// HandleMessageDisplayPrepare validates a message context strictly, mints a
// challenge for it, and returns only that challenge. It decrypts nothing and
// touches no key material — the group handle is recorded, not opened.
func HandleMessageDisplayPrepare(d Deps, payload json.RawMessage) proto.BaseResponse {
	d.Logger.Println("message display prepare request processing...")

	var req proto.MessageDisplayPrepareRequest
	if resp, ok := decodeMessageRequest(payload, &req); !ok {
		return resp
	}

	_, _, digest, resp, ok := messagePayloadBytes(req.IVB64, req.CiphertextB64)
	if !ok {
		return resp
	}

	challengeBytes := make([]byte, proto.MessageDisplayChallengeBytes)
	if err := d.FillRandom(challengeBytes); err != nil {
		d.Logger.Println("message display prepare error: challenge generation failed")
		return errs.CodeResponse(errs.ErrCodeInternal, "challenge generation failed")
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	context := messageDisplayContext{
		groupHandle:          req.GroupHandle,
		orgID:                req.OrgID,
		groupID:              req.GroupID,
		dekVersion:           req.DekVersion,
		messageSchemaVersion: req.MessageSchemaVersion,
		tokenExpiresAt:       req.TokenExpiresAt,
		auditTableSlot:       proto.MessageAuditTableSlot(req.AuditTableID),
		payloadSHA256:        digest,
	}
	if err := d.MessageChallenges.Put(challenge, context, d.Now()); err != nil {
		d.Logger.Println("message display prepare refused: challenge capacity reached")
		return messageFailure(proto.MessageErrorCodeDisplayBusy, "message display is busy")
	}

	d.Logger.Println("message display prepare successful")
	return proto.BaseResponse{Success: true, Data: proto.MessageDisplayPrepareResponseData{
		Challenge: challenge,
	}}
}

// HandleGroupDecryptWithAadForAppDisplay opens one message for browser display.
//
// The caller supplies structured context, never an AAD: messageDisplayAAD is
// built here from fields this handler validated, so a drag token (sealed with
// no AAD) and a credential payload (sealed under the credential canonical) fail
// the GCM tag even when the caller holds the right handle and names the right
// org, group, and version.
func HandleGroupDecryptWithAadForAppDisplay(d Deps, payload json.RawMessage) proto.BaseResponse {
	d.Logger.Println("message display request processing...")

	var req proto.GroupDecryptWithAadForAppDisplayRequest
	if resp, ok := decodeMessageRequest(payload, &req); !ok {
		return resp
	}

	iv, ciphertext, digest, resp, ok := messagePayloadBytes(req.IVB64, req.CiphertextB64)
	if !ok {
		return resp
	}

	now := d.Now()
	permit := req.Permit

	context, found := d.MessageChallenges.Peek(permit.Challenge, now)
	if !found {
		return messageNotAuthorized(d, "challenge")
	}
	if !messageDisplayBindingHolds(req, context, digest) {
		return messageNotAuthorized(d, "binding")
	}
	if !messageDisplayPermitWindowHolds(permit, now.Unix()) {
		return messageNotAuthorized(d, "permit window")
	}
	if err := d.ServerKeyVerifier.Verify(
		proto.MessageDisplayPermitCanonical(permit), permit.Signature, permit.ServerKeyVersion,
	); err != nil {
		// The verifier's message names the failing step and sometimes the key
		// version; neither belongs in a reply to a caller that just failed to
		// prove authorization.
		return messageNotAuthorized(d, "signature")
	}
	// Separate from the permit's own window and with no clock grace: a permit
	// stays valid for 30 seconds, the message does not.
	if now.Unix() >= permit.TokenExpiresAt {
		return messageExpired(d)
	}

	if _, consumed := d.MessageChallenges.Consume(permit.Challenge, now); !consumed {
		// Another call took it between the Peek above and here, or it expired in
		// that window. Either way this call is not the one that gets to open it.
		return messageNotAuthorized(d, "challenge")
	}

	aad := []byte(proto.MessageAADCanonical(
		req.OrgID, req.GroupID, req.DekVersion, req.MessageSchemaVersion, req.TokenExpiresAt,
	))

	var plaintext []byte
	var openErr error
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		opened, err := AESGCMOpenWithAAD(groupDEK, iv, ciphertext, aad)
		if err != nil {
			openErr = err
			return nil
		}
		plaintext = opened
		return nil
	})
	if useErr != nil {
		// The handle named by a consumed challenge is gone — closed or reaped
		// between prepare and display. The caller can no longer show it holds
		// the key, which is an authorization answer, not a crypto one.
		return messageNotAuthorized(d, "group handle")
	}
	if openErr != nil {
		return messageDecryptFailed(d, "gcm")
	}
	defer secure.Zeroize(plaintext)

	if len(plaintext) < proto.MessagePlaintextMinBytes || len(plaintext) > proto.MessagePlaintextMaxBytes {
		return messageDecryptFailed(d, "plaintext size")
	}
	if !utf8.Valid(plaintext) {
		// Not repaired with replacement characters: a message that does not
		// decode is not shown at all.
		return messageDecryptFailed(d, "utf-8")
	}

	// Re-read the clock rather than reusing `now`: the decrypt sat on the
	// session mutex, and a response that leaves here must not display a message
	// that expired while it waited.
	if d.Now().Unix() >= permit.TokenExpiresAt {
		return messageExpired(d)
	}

	d.Logger.Println("message display successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupDecryptWithAadForAppDisplayResponseData{
		PlaintextB64: base64.StdEncoding.EncodeToString(plaintext),
	}}
}

// ────────────────────────────────────────────────────────────────────────
// Decode / validate
// ────────────────────────────────────────────────────────────────────────

// decodeMessageRequest applies the size cap, the strict decode, and the
// request's own Validate. Every failure is one code — MESSAGE_INVALID_INPUT —
// with a message that names the problem but never echoes the payload.
func decodeMessageRequest(payload json.RawMessage, req proto.Validator) (proto.BaseResponse, bool) {
	if len(payload) > proto.MessageDisplayMaxRequestBytes {
		return messageInvalidInput("request exceeds the maximum size"), false
	}
	if err := strictDecodeJSON(payload, req); err != nil {
		return messageInvalidInput("invalid message request: " + err.Error()), false
	}
	if err := req.Validate(); err != nil {
		return messageInvalidInput(err.Error()), false
	}
	return proto.BaseResponse{}, true
}

// messagePayloadBytes decodes the sealed payload and computes the lowercase-hex
// SHA-256 over IV ‖ ciphertext ‖ tag — the value the permit binds and the
// Extension computes independently.
//
// Validate has already checked both fields decode and are the right size, so a
// failure here would be a bug rather than a caller error; the decode is still
// checked rather than assumed.
func messagePayloadBytes(ivB64, ciphertextB64 string) (iv, ciphertext []byte, digest string, resp proto.BaseResponse, ok bool) {
	iv, resp, ok = decodeBase64(ivB64, "iv_b64")
	if !ok {
		return nil, nil, "", resp, false
	}
	ciphertext, resp, ok = decodeBase64(ciphertextB64, "ciphertext_b64")
	if !ok {
		return nil, nil, "", resp, false
	}
	sum := sha256.New()
	sum.Write(iv)
	sum.Write(ciphertext)
	return iv, ciphertext, hex.EncodeToString(sum.Sum(nil)), proto.BaseResponse{}, true
}

// ────────────────────────────────────────────────────────────────────────
// Permit checks
// ────────────────────────────────────────────────────────────────────────

// messageDisplayBindingHolds reports whether the permit, the request, and the
// challenge this process minted all describe the same message.
//
// Three-way on purpose. Permit-against-request catches a permit reused for
// another payload; permit-against-challenge catches a request rewritten after
// the permit was signed; and the digest ties both to these exact bytes. Change
// any single field of the request and one of the twelve comparisons below
// fails — except account_id, which has no request counterpart and is held by
// the signature alone.
func messageDisplayBindingHolds(
	req proto.GroupDecryptWithAadForAppDisplayRequest,
	context messageDisplayContext,
	digest string,
) bool {
	permit := req.Permit
	requestAuditSlot := proto.MessageAuditTableSlot(req.AuditTableID)

	permitMatchesRequest := permit.OrgID == req.OrgID &&
		permit.GroupID == req.GroupID &&
		permit.DekVersion == req.DekVersion &&
		permit.MessageSchemaVersion == req.MessageSchemaVersion &&
		permit.TokenExpiresAt == req.TokenExpiresAt &&
		proto.MessageAuditTableSlot(permit.AuditTableID) == requestAuditSlot &&
		permit.PayloadSHA256 == digest

	challengeMatchesRequest := context.groupHandle == req.GroupHandle &&
		context.orgID == req.OrgID &&
		context.groupID == req.GroupID &&
		context.dekVersion == req.DekVersion &&
		context.messageSchemaVersion == req.MessageSchemaVersion &&
		context.tokenExpiresAt == req.TokenExpiresAt &&
		context.auditTableSlot == requestAuditSlot &&
		context.payloadSHA256 == digest

	return permitMatchesRequest && challengeMatchesRequest
}

// messageDisplayPermitWindowHolds checks the three timing rules the server
// promises to sign into every permit. The fixed 30-second span is checked, not
// assumed: a permit with a wider window was signed by something that is not
// following this contract.
func messageDisplayPermitWindowHolds(permit proto.MessageDisplayPermit, nowUnix int64) bool {
	if permit.IssuedAt > nowUnix+messageDisplayClockSkewSeconds {
		return false
	}
	if nowUnix >= permit.ExpiresAt {
		return false
	}
	return permit.ExpiresAt-permit.IssuedAt == proto.MessageDisplayPermitTTLSeconds
}

// ────────────────────────────────────────────────────────────────────────
// Failure responses
//
// All five domain codes travel in the existing envelope's error_code field.
// The messages are fixed strings: no server text, no request payload, no hint
// about which of the four authorization checks refused.
// ────────────────────────────────────────────────────────────────────────

func messageFailure(code, message string) proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(code), message)
}

func messageInvalidInput(message string) proto.BaseResponse {
	return messageFailure(proto.MessageErrorCodeInvalidInput, message)
}

func messageNotAuthorized(d Deps, stage string) proto.BaseResponse {
	// The stage name is a fixed token, logged for operators. The response says
	// only that authorization failed.
	d.Logger.Printf("message display not authorized (%s check)", stage)
	return messageFailure(proto.MessageErrorCodeDisplayNotAuthorized, "message display is not authorized")
}

func messageDecryptFailed(d Deps, stage string) proto.BaseResponse {
	d.Logger.Printf("message display decrypt failed (%s)", stage)
	return messageFailure(proto.MessageErrorCodeDecryptFailed, "message decrypt failed")
}

func messageExpired(d Deps) proto.BaseResponse {
	d.Logger.Println("message display refused: message token expired")
	return messageFailure(proto.MessageErrorCodeExpired, "message has expired")
}
