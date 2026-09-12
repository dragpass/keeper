// message_display_test.go — the two-step secure-message reveal, end to end and
// at every refusal.
//
// The golden vector (key, IV, AAD, ciphertext, tag) and both negative
// ciphertexts come from dragpass-control-plane
// docs/testing/fixtures/secure-message-overlay-v1.json. They are test-only
// values; the literals live here rather than being read from that file because
// this repo is built and tested on its own, and a fixture the test cannot reach
// is a fixture the test silently skips.
//
// The negatives matter as much as the positive: `negative_non_aad` and
// `negative_credential` are the same plaintext under the same key with no AAD
// and with the credential AAD. Both must fail here. That is the whole argument
// for why a plaintext-returning action does not widen into "the app can decrypt
// anything the org can".

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	msgKeyHex           = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	msgIVB64            = "AAECAwQFBgcICQoL"
	msgCiphertextB64    = "A3C3fJWEsWitLPL4wogfCKOw7kyEDi0ZGBHUj02jpBEqwI2uZsRFqiUr5i0="
	msgNonAADB64        = "A3C3fJWEsWitLPL4wogfCKOw7kyEDi0ZGBHUj8KbF8gKYS+W222mbALNcDg="
	msgCredentialAADB64 = "A3C3fJWEsWitLPL4wogfCKOw7kyEDi0ZGBHUj1AMCwjvOtyWplKD64lvmZs="
	msgPlaintext        = "DragPass message fixture v1\n"
	msgPlaintextB64     = "RHJhZ1Bhc3MgbWVzc2FnZSBmaXh0dXJlIHYxCg=="
	msgOrgID            = "11111111-1111-4111-8111-111111111111"
	msgGroupID          = "22222222-2222-4222-8222-222222222222"
	msgAuditTableID     = "33333333-3333-4333-8333-333333333333"
	msgAccountID        = "44444444-4444-4444-8444-444444444444"
	msgOtherUUID        = "55555555-5555-4555-8555-555555555555"
	msgDekVersion       = 7
	msgTokenExpiresAt   = 2000000000

	// msgNowUnix — a fixed "now" comfortably before the fixture's expiry
	// (2033-05-18), so the golden vector opens under a deterministic clock.
	msgNowUnix = 1700000000

	msgServerKeyVersion = 1
)

// ────────────────────────────────────────────────────────────────────────
// Harness
// ────────────────────────────────────────────────────────────────────────

// msgTestServerKey returns the RSA key the test double verifies against.
// Generated once per test binary — 2048-bit key generation is the single
// slowest thing in this file and nothing here needs a distinct key.
var msgTestServerKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("message display test: rsa key generation failed: " + err.Error())
	}
	return key
})

// msgTestVerifier is the ServerKeyVerifier double: one registered key at one
// version, real RSA-PSS verification. Unlike AlwaysOKVerifier it actually
// checks the canonical, which is the point — the signature has to be over the
// bytes the handler built, not over whatever the test happened to sign.
type msgTestVerifier struct {
	version uint
	public  *rsa.PublicKey
}

func (v msgTestVerifier) Verify(token string, sigB64 string, serverKeyVersion uint) error {
	if serverKeyVersion != v.version {
		// Same shape as the production path: an unknown version fails closed
		// before any signature math happens.
		return fmt.Errorf("failed to get server public key: version %d not pinned", serverKeyVersion)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	return crypto.VerifySignature(v.public, token, sig)
}

type msgTestClock struct {
	mu   sync.Mutex
	unix int64
}

func (c *msgTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Unix(c.unix, 0)
}

func (c *msgTestClock) advance(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unix += seconds
}

type msgFixture struct {
	deps   Deps
	log    *logger.MemoryLogger
	clock  *msgTestClock
	handle string
	key    *rsa.PrivateKey
}

func newMsgFixture(t *testing.T) *msgFixture {
	t.Helper()
	deps, log, _ := newTestDeps(t)
	clock := &msgTestClock{unix: msgNowUnix}
	deps.Clock = clock.now
	key := msgTestServerKey()
	deps.ServerKeyVerifier = msgTestVerifier{version: msgServerKeyVersion, public: &key.PublicKey}
	f := &msgFixture{deps: deps, log: log, clock: clock, key: key}
	f.handle = f.openFixtureHandle(t)
	return f
}

// openFixtureHandle registers the fixture Group DEK and returns its handle.
// Every handle in this file holds the same key, so a "wrong handle" case tests
// the binding rather than the crypto.
func (f *msgFixture) openFixtureHandle(t *testing.T) string {
	t.Helper()
	raw, err := hex.DecodeString(msgKeyHex)
	if err != nil {
		t.Fatalf("decode fixture key: %v", err)
	}
	handle, _, err := f.deps.GroupSessions.Open(raw)
	if err != nil {
		t.Fatalf("open group session: %v", err)
	}
	t.Cleanup(func() { f.deps.GroupSessions.Close(handle) })
	return handle
}

// request returns the display request for the golden vector, minus the permit.
func (f *msgFixture) request() proto.GroupDecryptWithAadForAppDisplayRequest {
	return proto.GroupDecryptWithAadForAppDisplayRequest{
		GroupHandle:          f.handle,
		OrgID:                msgOrgID,
		GroupID:              msgGroupID,
		DekVersion:           msgDekVersion,
		MessageSchemaVersion: proto.MessageSchemaVersion,
		TokenExpiresAt:       msgTokenExpiresAt,
		AuditTableID:         nil,
		IVB64:                msgIVB64,
		CiphertextB64:        msgCiphertextB64,
	}
}

func msgPrepareRequest(r proto.GroupDecryptWithAadForAppDisplayRequest) proto.MessageDisplayPrepareRequest {
	return proto.MessageDisplayPrepareRequest{
		GroupHandle:          r.GroupHandle,
		OrgID:                r.OrgID,
		GroupID:              r.GroupID,
		DekVersion:           r.DekVersion,
		MessageSchemaVersion: r.MessageSchemaVersion,
		TokenExpiresAt:       r.TokenExpiresAt,
		AuditTableID:         r.AuditTableID,
		IVB64:                r.IVB64,
		CiphertextB64:        r.CiphertextB64,
	}
}

func msgMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// prepare runs the prepare action for a request and returns the challenge.
func (f *msgFixture) prepare(t *testing.T, r proto.GroupDecryptWithAadForAppDisplayRequest) string {
	t.Helper()
	resp := HandleMessageDisplayPrepare(f.deps, msgMarshal(t, msgPrepareRequest(r)))
	if !resp.Success {
		t.Fatalf("prepare failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.MessageDisplayPrepareResponseData)
	if !ok {
		t.Fatalf("prepare data type = %T", resp.Data)
	}
	return data.Challenge
}

// unsignedPermit builds the permit a correct server would sign for this request.
func (f *msgFixture) unsignedPermit(challenge string, r proto.GroupDecryptWithAadForAppDisplayRequest) proto.MessageDisplayPermit {
	now := f.clock.now().Unix()
	return proto.MessageDisplayPermit{
		Challenge:            challenge,
		GroupID:              r.GroupID,
		DekVersion:           r.DekVersion,
		MessageSchemaVersion: r.MessageSchemaVersion,
		TokenExpiresAt:       r.TokenExpiresAt,
		AuditTableID:         r.AuditTableID,
		PayloadSHA256:        msgDigestOf(r.IVB64, r.CiphertextB64),
		AccountID:            msgAccountID,
		OrgID:                r.OrgID,
		IssuedAt:             now,
		ExpiresAt:            now + proto.MessageDisplayPermitTTLSeconds,
		ServerKeyVersion:     msgServerKeyVersion,
	}
}

func (f *msgFixture) sign(t *testing.T, p proto.MessageDisplayPermit) proto.MessageDisplayPermit {
	t.Helper()
	sig, err := crypto.SignData(f.key, proto.MessageDisplayPermitCanonical(p))
	if err != nil {
		t.Fatalf("sign permit: %v", err)
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}

func (f *msgFixture) signedPermit(t *testing.T, challenge string, r proto.GroupDecryptWithAadForAppDisplayRequest) proto.MessageDisplayPermit {
	t.Helper()
	return f.sign(t, f.unsignedPermit(challenge, r))
}

func (f *msgFixture) display(t *testing.T, r proto.GroupDecryptWithAadForAppDisplayRequest) proto.BaseResponse {
	t.Helper()
	return HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, r))
}

// authorized runs the whole happy path and returns the response, so the tests
// that break one thing can start from a flow that is known to work.
func (f *msgFixture) authorized(t *testing.T) proto.GroupDecryptWithAadForAppDisplayRequest {
	t.Helper()
	req := f.request()
	challenge := f.prepare(t, req)
	req.Permit = f.signedPermit(t, challenge, req)
	return req
}

func msgDigestOf(ivB64, ciphertextB64 string) string {
	_, _, digest, _, ok := messagePayloadBytes(ivB64, ciphertextB64)
	if !ok {
		panic("message display test: fixture payload does not decode")
	}
	return digest
}

func msgStr(v string) *string { return &v }

func assertMsgFailure(t *testing.T, resp proto.BaseResponse, wantCode string) {
	t.Helper()
	if resp.Success {
		t.Fatalf("expected failure %s, got success", wantCode)
	}
	if resp.ErrorCode != wantCode {
		t.Fatalf("error_code = %q, want %q (message %q)", resp.ErrorCode, wantCode, resp.Error)
	}
}

func assertMsgPlaintext(t *testing.T, resp proto.BaseResponse) {
	t.Helper()
	if !resp.Success {
		t.Fatalf("expected success, got %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.GroupDecryptWithAadForAppDisplayResponseData)
	if !ok {
		t.Fatalf("display data type = %T", resp.Data)
	}
	if data.PlaintextB64 != msgPlaintextB64 {
		t.Fatalf("plaintext_b64 = %q, want %q", data.PlaintextB64, msgPlaintextB64)
	}
}

// ────────────────────────────────────────────────────────────────────────
// prepare
// ────────────────────────────────────────────────────────────────────────

func TestMessageDisplayPrepare_MintsChallengeAndRemembersDigest(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	challenge := f.prepare(t, req)

	if len(challenge) != proto.MessageDisplayChallengeChars {
		t.Fatalf("challenge length = %d, want %d", len(challenge), proto.MessageDisplayChallengeChars)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("challenge must be unpadded Base64URL, got %q", challenge)
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != proto.MessageDisplayChallengeBytes {
		t.Fatalf("challenge must decode to %d bytes: %v", proto.MessageDisplayChallengeBytes, err)
	}

	context, ok := f.deps.MessageChallenges.Peek(challenge, f.clock.now())
	if !ok {
		t.Fatal("prepare did not store the challenge")
	}
	wantDigest := msgDigestOf(msgIVB64, msgCiphertextB64)
	if context.payloadSHA256 != wantDigest {
		t.Fatalf("stored digest = %q, want SHA256(IV‖ct‖tag) = %q", context.payloadSHA256, wantDigest)
	}
	if context.payloadSHA256 != strings.ToLower(context.payloadSHA256) {
		t.Fatalf("stored digest must be lowercase hex, got %q", context.payloadSHA256)
	}
	if context.groupHandle != req.GroupHandle || context.orgID != msgOrgID || context.groupID != msgGroupID ||
		context.dekVersion != msgDekVersion || context.tokenExpiresAt != msgTokenExpiresAt ||
		context.auditTableSlot != "-" {
		t.Fatalf("stored context does not match the request: %+v", context)
	}
}

func TestMessageDisplayPrepare_MintsDistinctChallenges(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	first := f.prepare(t, req)
	second := f.prepare(t, req)
	if first == second {
		t.Fatal("two prepares produced the same challenge")
	}
}

// TestMessageDisplayPrepare_NinthConcurrentIsBusy — capacity is refused, not
// made room for. Evicting the oldest entry would let any caller flush a
// challenge it does not own.
func TestMessageDisplayPrepare_NinthConcurrentIsBusy(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	for i := 0; i < messageDisplayMaxChallenges; i++ {
		f.prepare(t, req)
	}
	resp := HandleMessageDisplayPrepare(f.deps, msgMarshal(t, msgPrepareRequest(req)))
	assertMsgFailure(t, resp, proto.MessageErrorCodeDisplayBusy)
	if got := f.deps.MessageChallenges.Len(); got != messageDisplayMaxChallenges {
		t.Fatalf("live challenges = %d, want %d", got, messageDisplayMaxChallenges)
	}
}

// TestMessageDisplayPrepare_ExpiredChallengesAreSweptAndFreeCapacity — the
// 30-second deadline is real: an expired entry is gone for the display step and
// does not hold a capacity slot.
func TestMessageDisplayPrepare_ExpiredChallengesAreSweptAndFreeCapacity(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	var challenges []string
	for i := 0; i < messageDisplayMaxChallenges; i++ {
		challenges = append(challenges, f.prepare(t, req))
	}

	f.clock.advance(int64(messageDisplayChallengeTTL/time.Second) + 1)

	if _, ok := f.deps.MessageChallenges.Peek(challenges[0], f.clock.now()); ok {
		t.Fatal("expired challenge is still usable")
	}
	// A fresh prepare now succeeds: the sweep reclaimed the slots.
	fresh := f.prepare(t, req)
	if _, ok := f.deps.MessageChallenges.Peek(fresh, f.clock.now()); !ok {
		t.Fatal("challenge minted after the sweep is missing")
	}
	if got := f.deps.MessageChallenges.Len(); got != 1 {
		t.Fatalf("live challenges after sweep = %d, want 1", got)
	}
}

func TestMessageDisplayPrepare_ExpiredChallengeCannotDisplay(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	challenge := f.prepare(t, req)
	f.clock.advance(int64(messageDisplayChallengeTTL/time.Second) + 1)
	req.Permit = f.signedPermit(t, challenge, req)

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
}

// ────────────────────────────────────────────────────────────────────────
// display — the happy path
// ────────────────────────────────────────────────────────────────────────

func TestMessageDisplay_OpensGoldenVector(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)

	assertMsgPlaintext(t, f.display(t, req))

	if got := f.deps.MessageChallenges.Len(); got != 0 {
		t.Fatalf("challenge survived a successful display: %d entries", got)
	}
}

// TestMessageDisplay_OpensAuditMessage — an audit message carries a table id in
// the AAD-adjacent context and in the permit canonical. The payload is the same
// golden ciphertext because the audit table is not part of the message AAD; the
// slot is bound by the signature instead.
func TestMessageDisplay_OpensAuditMessage(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	req.AuditTableID = msgStr(msgAuditTableID)
	challenge := f.prepare(t, req)
	req.Permit = f.signedPermit(t, challenge, req)

	assertMsgPlaintext(t, f.display(t, req))
}

// TestMessageDisplay_PlaintextNeverReachesTheLog — the response is the approved
// exception; the log is not. Checked for the plaintext, its Base64, and the
// fixture key.
func TestMessageDisplay_PlaintextNeverReachesTheLog(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	assertMsgPlaintext(t, f.display(t, req))

	for _, forbidden := range []string{
		msgPlaintext,
		strings.TrimSuffix(msgPlaintext, "\n"),
		msgPlaintextB64,
		msgKeyHex,
		msgCiphertextB64,
	} {
		if f.log.Contains(forbidden) {
			t.Fatalf("log leaked %q: %v", forbidden, f.log.Messages())
		}
	}
}

// TestMessageDisplay_ReusedChallengeIsRefused — one prepare, one reveal. A
// retry starts from a new prepare.
func TestMessageDisplay_ReusedChallengeIsRefused(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	assertMsgPlaintext(t, f.display(t, req))
	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
}

// TestMessageDisplay_ConcurrentSameChallengeLeavesOneWinner — Consume is the
// single gate. Two callers race it; exactly one opens the message.
func TestMessageDisplay_ConcurrentSameChallengeLeavesOneWinner(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	payload := msgMarshal(t, req)

	const racers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	responses := make([]proto.BaseResponse, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			responses[i] = HandleGroupDecryptWithAadForAppDisplay(f.deps, payload)
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, resp := range responses {
		if resp.Success {
			successes++
			assertMsgPlaintext(t, resp)
			continue
		}
		if resp.ErrorCode != proto.MessageErrorCodeDisplayNotAuthorized {
			t.Fatalf("loser error_code = %q, want %q", resp.ErrorCode, proto.MessageErrorCodeDisplayNotAuthorized)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent displays succeeded %d times, want exactly 1", successes)
	}
}

// ────────────────────────────────────────────────────────────────────────
// display — the AAD domain separation
// ────────────────────────────────────────────────────────────────────────

// TestMessageDisplay_RejectsForeignAADCiphertexts — the same plaintext, the
// same key, the same IV, sealed with no AAD and with the credential AAD. Both
// fail, and both spend the challenge: the caller had a valid permit, so the
// authorization was used even though the open failed.
func TestMessageDisplay_RejectsForeignAADCiphertexts(t *testing.T) {
	cases := []struct {
		name       string
		ciphertext string
	}{
		{"drag token sealed without an AAD", msgNonAADB64},
		{"credential payload sealed under the credential AAD", msgCredentialAADB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.request()
			req.CiphertextB64 = tc.ciphertext
			challenge := f.prepare(t, req)
			req.Permit = f.signedPermit(t, challenge, req)

			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDecryptFailed)
			if got := f.deps.MessageChallenges.Len(); got != 0 {
				t.Fatalf("challenge survived a tag failure: %d entries", got)
			}
			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
			if f.log.Contains(msgPlaintext) {
				t.Fatalf("log leaked the plaintext: %v", f.log.Messages())
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// display — binding
// ────────────────────────────────────────────────────────────────────────

// TestMessageDisplay_RequestMutatedAfterSigningIsRefused — the permit is signed
// over the real request, then one field of the request is changed. Every field
// the signature covers has to break the match.
//
// message_schema_version is absent on purpose: any value but 1 is refused
// structurally (MESSAGE_INVALID_INPUT), which is the stronger answer.
// TestMessageDisplay_RejectsUnsupportedSchema covers it.
func TestMessageDisplay_RequestMutatedAfterSigningIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		apply func(t *testing.T, f *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest)
	}{
		{"org_id", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.OrgID = msgOtherUUID
		}},
		{"group_id", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.GroupID = msgOtherUUID
		}},
		{"dek_version", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.DekVersion = msgDekVersion + 1
		}},
		{"token_expires_at", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.TokenExpiresAt = msgTokenExpiresAt + 1
		}},
		{"audit_table_id", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.AuditTableID = msgStr(msgAuditTableID)
		}},
		{"iv_b64", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.IVB64 = "CwoJCAcGBQQDAgEA"
		}},
		{"ciphertext_b64", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.CiphertextB64 = msgNonAADB64
		}},
		{"group_handle", func(t *testing.T, f *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			// A second handle over the same key: the challenge remembers which
			// handle was prepared, so the swap is refused on binding rather than
			// on the crypto.
			r.GroupHandle = f.openFixtureHandle(t)
		}},
		{"permit.account_id", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.Permit.AccountID = msgOtherUUID
		}},
		{"permit.payload_sha256", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.Permit.PayloadSHA256 = msgDigestOf(msgIVB64, msgNonAADB64)
		}},
		{"permit.issued_at", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.Permit.IssuedAt--
			r.Permit.ExpiresAt--
		}},
		{"permit.server_key_version", func(_ *testing.T, _ *msgFixture, r *proto.GroupDecryptWithAadForAppDisplayRequest) {
			r.Permit.ServerKeyVersion = msgServerKeyVersion + 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.authorized(t)
			tc.apply(t, f, &req)

			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
			// A refusal before consumption: a caller that cannot authorize must
			// not be able to burn somebody else's pending reveal.
			if got := f.deps.MessageChallenges.Len(); got != 1 {
				t.Fatalf("challenge count after a refused display = %d, want 1", got)
			}
		})
	}
}

// TestMessageDisplay_ValidlySignedPermitForAnotherMessageIsRefused — the permit
// is internally consistent and correctly signed; it simply describes a
// different message than the request and the challenge do. The signature alone
// is not authorization.
func TestMessageDisplay_ValidlySignedPermitForAnotherMessageIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		apply func(p *proto.MessageDisplayPermit)
	}{
		{"org_id", func(p *proto.MessageDisplayPermit) { p.OrgID = msgOtherUUID }},
		{"group_id", func(p *proto.MessageDisplayPermit) { p.GroupID = msgOtherUUID }},
		{"dek_version", func(p *proto.MessageDisplayPermit) { p.DekVersion = msgDekVersion + 1 }},
		{"token_expires_at", func(p *proto.MessageDisplayPermit) { p.TokenExpiresAt = msgTokenExpiresAt + 1 }},
		{"audit_table_id", func(p *proto.MessageDisplayPermit) { p.AuditTableID = msgStr(msgAuditTableID) }},
		{"payload_sha256", func(p *proto.MessageDisplayPermit) {
			p.PayloadSHA256 = msgDigestOf(msgIVB64, msgCredentialAADB64)
		}},
		{"challenge", func(p *proto.MessageDisplayPermit) {
			p.Challenge = "-XNnLWZpeHR1cmUtY2hhbGxlbmdlLTMyLWJ5dGVzI_E"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.request()
			challenge := f.prepare(t, req)
			permit := f.unsignedPermit(challenge, req)
			tc.apply(&permit)
			req.Permit = f.sign(t, permit)

			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
			if got := f.deps.MessageChallenges.Len(); got != 1 {
				t.Fatalf("challenge count after a refused display = %d, want 1", got)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// display — signature, key version, permit window
// ────────────────────────────────────────────────────────────────────────

func TestMessageDisplay_TamperedSignatureIsRefused(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	sig, err := base64.StdEncoding.DecodeString(req.Permit.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig[len(sig)-1] ^= 0xff
	req.Permit.Signature = base64.StdEncoding.EncodeToString(sig)

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
}

// TestMessageDisplay_UnknownServerKeyVersionFailsClosed — the permit is signed
// over its own canonical, so the only thing wrong is the version. A version the
// Keeper has not pinned is a refusal, never a fallback to the active key.
func TestMessageDisplay_UnknownServerKeyVersionFailsClosed(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	challenge := f.prepare(t, req)
	permit := f.unsignedPermit(challenge, req)
	permit.ServerKeyVersion = msgServerKeyVersion + 1
	req.Permit = f.sign(t, permit)

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
}

func TestMessageDisplay_PermitWindowIsEnforced(t *testing.T) {
	cases := []struct {
		name  string
		apply func(now int64, p *proto.MessageDisplayPermit)
	}{
		{"issued_at beyond the 5s skew", func(now int64, p *proto.MessageDisplayPermit) {
			p.IssuedAt = now + 6
			p.ExpiresAt = p.IssuedAt + proto.MessageDisplayPermitTTLSeconds
		}},
		{"window wider than 30s", func(now int64, p *proto.MessageDisplayPermit) {
			p.IssuedAt = now
			p.ExpiresAt = now + proto.MessageDisplayPermitTTLSeconds + 1
		}},
		{"window narrower than 30s", func(now int64, p *proto.MessageDisplayPermit) {
			p.IssuedAt = now
			p.ExpiresAt = now + proto.MessageDisplayPermitTTLSeconds - 1
		}},
		{"already expired", func(now int64, p *proto.MessageDisplayPermit) {
			p.IssuedAt = now - 40
			p.ExpiresAt = p.IssuedAt + proto.MessageDisplayPermitTTLSeconds
		}},
		{"expires exactly now", func(now int64, p *proto.MessageDisplayPermit) {
			p.IssuedAt = now - proto.MessageDisplayPermitTTLSeconds
			p.ExpiresAt = now
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.request()
			challenge := f.prepare(t, req)
			permit := f.unsignedPermit(challenge, req)
			tc.apply(f.clock.now().Unix(), &permit)
			req.Permit = f.sign(t, permit)

			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
		})
	}
}

// TestMessageDisplay_IssuedAtWithinSkewIsAccepted — the 5-second tolerance is
// real and is the only clock grace anywhere in this flow.
func TestMessageDisplay_IssuedAtWithinSkewIsAccepted(t *testing.T) {
	f := newMsgFixture(t)
	req := f.request()
	challenge := f.prepare(t, req)
	permit := f.unsignedPermit(challenge, req)
	permit.IssuedAt = f.clock.now().Unix() + messageDisplayClockSkewSeconds
	permit.ExpiresAt = permit.IssuedAt + proto.MessageDisplayPermitTTLSeconds
	req.Permit = f.sign(t, permit)

	assertMsgPlaintext(t, f.display(t, req))
}

// ────────────────────────────────────────────────────────────────────────
// display — message expiry
// ────────────────────────────────────────────────────────────────────────

// TestMessageDisplay_ExpiredTokenIsRefused — the message's own expiry gets no
// grace at all, and it is a distinct code from an authorization failure: the
// caller was allowed, the message simply is not readable any more.
func TestMessageDisplay_ExpiredTokenIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance int64
	}{
		{"one second past expiry", 2},
		{"exactly at expiry", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.request()
			req.TokenExpiresAt = f.clock.now().Unix() + 1
			challenge := f.prepare(t, req)

			f.clock.advance(tc.advance)
			req.Permit = f.signedPermit(t, challenge, req)

			assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeExpired)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// display — handle lifecycle
// ────────────────────────────────────────────────────────────────────────

// TestMessageDisplay_ClosingTheHandleDropsPendingChallenges — the key that
// would open those messages is gone, so the permission goes with it rather than
// waiting out its deadline.
func TestMessageDisplay_ClosingTheHandleDropsPendingChallenges(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)

	closeResp := HandleGroupSessionClose(f.deps, proto.GroupSessionCloseRequest{GroupHandle: req.GroupHandle})
	if !closeResp.Success {
		t.Fatalf("group session close failed: %s", closeResp.Error)
	}
	if got := f.deps.MessageChallenges.Len(); got != 0 {
		t.Fatalf("challenges survived the handle close: %d entries", got)
	}

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
}

// TestMessageDisplay_HandleDroppedWithoutCloseIsRefused — the same answer when
// the handle disappears behind the challenge's back (a reap, a store the
// Extension closed directly): the caller can no longer show it holds the key.
func TestMessageDisplay_HandleDroppedWithoutCloseIsRefused(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)

	f.deps.GroupSessions.Close(req.GroupHandle) // no challenge purge

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
	if got := f.deps.MessageChallenges.Len(); got != 0 {
		t.Fatalf("challenge survived a consumed reveal: %d entries", got)
	}
}

// TestMessageDisplay_PurgeOnlyDropsTheClosedHandle — closing one handle must
// not cancel a reveal pending on another.
func TestMessageDisplay_PurgeOnlyDropsTheClosedHandle(t *testing.T) {
	f := newMsgFixture(t)
	kept := f.authorized(t)

	other := f.openFixtureHandle(t)
	HandleGroupSessionClose(f.deps, proto.GroupSessionCloseRequest{GroupHandle: other})

	assertMsgPlaintext(t, f.display(t, kept))
}

// ────────────────────────────────────────────────────────────────────────
// display — strict decoding
// ────────────────────────────────────────────────────────────────────────

// msgPayloadMap renders an authorized request as a mutable JSON object, so the
// strict-decoding cases can add, drop, and duplicate keys.
func msgPayloadMap(t *testing.T, r proto.GroupDecryptWithAadForAppDisplayRequest) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(msgMarshal(t, r), &object); err != nil {
		t.Fatalf("re-read payload: %v", err)
	}
	return object
}

func TestMessageDisplay_RejectsUnknownField(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	object := msgPayloadMap(t, req)
	// The field the whole design exists to not have.
	object["aad_b64"] = base64.StdEncoding.EncodeToString([]byte("dragpass.message|1|x"))

	resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, object))
	assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
}

func TestMessageDisplay_RejectsUnknownPermitField(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	object := msgPayloadMap(t, req)
	permit, _ := object["permit"].(map[string]any)
	permit["scope"] = "everything"

	resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, object))
	assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
}

func TestMessageDisplay_RejectsMissingField(t *testing.T) {
	for _, field := range []string{"org_id", "audit_table_id", "iv_b64", "permit"} {
		t.Run(field, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.authorized(t)
			object := msgPayloadMap(t, req)
			delete(object, field)

			resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, object))
			assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
		})
	}
}

func TestMessageDisplay_RejectsMissingPermitField(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	object := msgPayloadMap(t, req)
	permit, _ := object["permit"].(map[string]any)
	delete(permit, "audit_table_id")

	resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, object))
	assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
}

// TestMessageDisplay_RejectsDuplicateKeys — the reason this action does not go
// through the dispatcher's shared decoder. json.Unmarshal keeps the last value
// of a duplicate key, so a request could verify under one dek_version and
// decrypt under another.
func TestMessageDisplay_RejectsDuplicateKeys(t *testing.T) {
	cases := []struct {
		name  string
		build func(body string) string
	}{
		{"top level", func(body string) string {
			return strings.Replace(body, `"dek_version":7`, `"dek_version":7,"dek_version":9`, 1)
		}},
		{"inside permit", func(body string) string {
			// The permit's own dek_version, which appears after account_id in the
			// marshalled object.
			return strings.Replace(body, `"payload_sha256":`, `"dek_version":9,"payload_sha256":`, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMsgFixture(t)
			req := f.authorized(t)
			body := string(msgMarshal(t, req))
			mutated := tc.build(body)
			if mutated == body {
				t.Fatal("test did not inject a duplicate key")
			}

			resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, json.RawMessage(mutated))
			assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
		})
	}
}

func TestMessageDisplay_RejectsOversizeRequest(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	object := msgPayloadMap(t, req)
	object["org_id"] = strings.Repeat("x", proto.MessageDisplayMaxRequestBytes)

	resp := HandleGroupDecryptWithAadForAppDisplay(f.deps, msgMarshal(t, object))
	assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
	if !strings.Contains(resp.Error, "maximum size") {
		t.Fatalf("oversize request must be refused by length, got %q", resp.Error)
	}
}

func TestMessageDisplay_RejectsUnsupportedSchema(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	req.MessageSchemaVersion = 2

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeInvalidInput)
}

func TestMessageDisplayPrepare_RejectsUnknownField(t *testing.T) {
	f := newMsgFixture(t)
	object := msgPayloadMap(t, f.request())
	delete(object, "permit")
	object["aad_b64"] = "eA=="

	resp := HandleMessageDisplayPrepare(f.deps, msgMarshal(t, object))
	assertMsgFailure(t, resp, proto.MessageErrorCodeInvalidInput)
}

func TestMessageDisplayPrepare_RejectsEmptyPayload(t *testing.T) {
	f := newMsgFixture(t)
	assertMsgFailure(t, HandleMessageDisplayPrepare(f.deps, nil), proto.MessageErrorCodeInvalidInput)
	assertMsgFailure(t, HandleMessageDisplayPrepare(f.deps, json.RawMessage(`{}`)), proto.MessageErrorCodeInvalidInput)
}

// ────────────────────────────────────────────────────────────────────────
// fail-closed wiring
// ────────────────────────────────────────────────────────────────────────

// TestMessageDisplay_WithoutAChallengeStoreFailsClosed — a Deps built without
// the store cannot mint a challenge and cannot consume one. The action is
// unavailable rather than unguarded.
func TestMessageDisplay_WithoutAChallengeStoreFailsClosed(t *testing.T) {
	f := newMsgFixture(t)
	req := f.authorized(t)
	f.deps.MessageChallenges = nil

	assertMsgFailure(t, f.display(t, req), proto.MessageErrorCodeDisplayNotAuthorized)
	assertMsgFailure(t,
		HandleMessageDisplayPrepare(f.deps, msgMarshal(t, msgPrepareRequest(f.request()))),
		proto.MessageErrorCodeDisplayBusy)
}
