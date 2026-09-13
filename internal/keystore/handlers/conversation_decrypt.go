// conversation_decrypt.go — the DragPass 1:1 chat reveal.
//
// HandleConversationDecryptBatchForAppDisplay verifies a server-signed
// conversation-read-permit and opens a page of one conversation's messages
// under the conversation DEK behind an opaque group handle, returning the
// plaintexts. It is the protocol's second plaintext-returning response, so the
// interesting part of this file is everything that has to hold before any
// plaintext is produced:
//
//	strict decode (no unknown / duplicate / missing field, 2 MiB cap,
//	  <=200 messages, each ciphertext 17..8208B)
//	  → structural validation
//	  → the request and the permit agree on org_id / conversation_id /
//	    dek_version
//	  → the permit window holds (issued_at <= now+5, now < expires_at,
//	    expires_at - issued_at == 300)
//	  → the server signature verifies under the named key version (unknown
//	    version fails closed, no active-key fallback)
//	  → every message opens under an AAD the Keeper built, not one it was given
//	  → every plaintext is well-formed UTF-8; any failure refuses the whole
//	    batch with no partial output
//
// The order is the contract (dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-1to1-implementation.md §5), not an
// implementation detail. Unlike the Secure Message reveal there is no
// per-message challenge: opening the group handle from a wrapped grant is
// itself the key-possession proof, so possession + permit are the two axes.
//
// Like the message display actions this takes the raw payload rather than a
// decoded request. The dispatcher's shared `process` helper decodes with plain
// json.Unmarshal, which cannot refuse a duplicate key — and a duplicate key in
// a signature-bound request means verifying one value and decrypting under
// another. See strict_json.go.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// chatReadPermitClockSkewSeconds — how far into the future a permit's issued_at
// may sit. Covers ordinary server/client clock drift and nothing more.
const chatReadPermitClockSkewSeconds = 5

// HandleConversationDecryptBatchForAppDisplay opens a batch of chat messages
// for browser display.
//
// The caller supplies structured context, never an AAD: the chat AAD is built
// here from the permit's validated fields, so a drag token (no AAD), a Secure
// Message (message canonical), and a credential payload (credential canonical)
// fail the GCM tag even when the caller holds the right handle and names the
// right conversation.
func HandleConversationDecryptBatchForAppDisplay(d Deps, payload json.RawMessage) proto.BaseResponse {
	d.Logger.Println("conversation decrypt batch request processing...")

	var req proto.ConversationDecryptBatchForAppDisplayRequest
	if resp, ok := decodeConversationRequest(payload, &req); !ok {
		return resp
	}

	permit := req.Permit
	now := d.Now().Unix()

	if !conversationBindingHolds(req) {
		return chatNotAuthorized(d, "binding")
	}
	if !conversationReadPermitWindowHolds(permit, now) {
		return chatNotAuthorized(d, "permit window")
	}
	if err := d.ServerKeyVerifier.Verify(
		proto.ConversationReadPermitCanonical(permit), permit.Signature, permit.ServerKeyVersion,
	); err != nil {
		// The verifier's message names the failing step and sometimes the key
		// version; neither belongs in a reply to a caller that just failed to
		// prove authorization.
		return chatNotAuthorized(d, "signature")
	}

	// AAD from the permit's structured fields, never from the request body. The
	// binding check above already proved the request agrees with the permit.
	aad := []byte(proto.ChatAADCanonical(permit.OrgID, permit.ConversationID, permit.DekVersion))

	plaintexts := make([][]byte, len(req.Messages))
	// Zeroize every opened plaintext on the way out, on both the success and the
	// failure path: the encoded copies leave, the raw buffers do not.
	defer func() {
		for _, pt := range plaintexts {
			secure.Zeroize(pt)
		}
	}()

	var openFailed bool
	useErr := d.GroupSessions.Use(req.GroupHandle, func(dek []byte) error {
		for i := range req.Messages {
			iv, err := base64.StdEncoding.DecodeString(req.Messages[i].IVB64)
			if err != nil {
				openFailed = true
				return nil
			}
			ciphertext, err := base64.StdEncoding.DecodeString(req.Messages[i].CiphertextB64)
			if err != nil {
				openFailed = true
				return nil
			}
			plaintext, err := AESGCMOpenWithAAD(dek, iv, ciphertext, aad)
			if err != nil {
				// One message failing tag / AAD refuses the whole batch: one
				// conversation at one version is one key/AAD family, so a failure
				// is a tamper or foreign-ciphertext signal, not a stray row.
				openFailed = true
				return nil
			}
			if !utf8.Valid(plaintext) {
				secure.Zeroize(plaintext)
				openFailed = true
				return nil
			}
			plaintexts[i] = plaintext
		}
		return nil
	})
	if useErr != nil {
		// The handle is gone — closed or reaped. The caller can no longer show
		// it holds the key, which is an authorization answer, not a crypto one.
		return chatNotAuthorized(d, "group handle")
	}
	if openFailed {
		return chatDecryptFailed(d)
	}

	out := make([]string, len(plaintexts))
	for i, plaintext := range plaintexts {
		out[i] = base64.StdEncoding.EncodeToString(plaintext)
	}

	d.Logger.Println("conversation decrypt batch successful")
	return proto.BaseResponse{Success: true, Data: proto.ConversationDecryptBatchForAppDisplayResponseData{
		PlaintextB64: out,
	}}
}

// decodeConversationRequest applies the size cap, the strict decode, and the
// request's own Validate. Every failure is one code — CHAT_INVALID_INPUT — with
// a message that names the problem but never echoes the payload.
func decodeConversationRequest(payload json.RawMessage, req proto.Validator) (proto.BaseResponse, bool) {
	if len(payload) > proto.ConversationDecryptMaxRequestBytes {
		return chatInvalidInput("request exceeds the maximum size"), false
	}
	if err := strictDecodeJSON(payload, req); err != nil {
		return chatInvalidInput("invalid conversation request: " + err.Error()), false
	}
	if err := req.Validate(); err != nil {
		return chatInvalidInput(err.Error()), false
	}
	return proto.BaseResponse{}, true
}

// conversationBindingHolds reports whether the permit and the request describe
// the same conversation at the same version. account_id has no request
// counterpart and is held by the signature alone.
func conversationBindingHolds(req proto.ConversationDecryptBatchForAppDisplayRequest) bool {
	p := req.Permit
	return p.OrgID == req.OrgID &&
		p.ConversationID == req.ConversationID &&
		p.DekVersion == req.DekVersion
}

// conversationReadPermitWindowHolds checks the three timing rules the server
// promises to sign into every permit. The fixed 300-second span is checked, not
// assumed: a permit with a wider window was signed by something that is not
// following this contract.
func conversationReadPermitWindowHolds(p proto.ConversationReadPermit, nowUnix int64) bool {
	if p.IssuedAt > nowUnix+chatReadPermitClockSkewSeconds {
		return false
	}
	if nowUnix >= p.ExpiresAt {
		return false
	}
	return p.ExpiresAt-p.IssuedAt == proto.ChatReadPermitTTLSeconds
}

// ────────────────────────────────────────────────────────────────────────
// Failure responses. All three domain codes travel in the existing envelope's
// error_code field. The messages are fixed strings: no server text, no request
// payload, no hint about which authorization check refused.
// ────────────────────────────────────────────────────────────────────────

func chatFailure(code, message string) proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(code), message)
}

func chatInvalidInput(message string) proto.BaseResponse {
	return chatFailure(proto.ChatErrorCodeInvalidInput, message)
}

func chatNotAuthorized(d Deps, stage string) proto.BaseResponse {
	// The stage name is a fixed token, logged for operators. The response says
	// only that authorization failed.
	d.Logger.Printf("conversation decrypt not authorized (%s check)", stage)
	return chatFailure(proto.ChatErrorCodePermitNotAuthorized, "conversation permit is not authorized")
}

func chatDecryptFailed(d Deps) proto.BaseResponse {
	d.Logger.Println("conversation decrypt failed")
	return chatFailure(proto.ChatErrorCodeDecryptFailed, "conversation decrypt failed")
}
