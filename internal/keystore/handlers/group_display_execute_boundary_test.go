package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"github.com/dragpass/keeper/config"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func preparedDisplayExecution(t *testing.T) (*auditFixture, proto.CurrentGroupDisplayExecuteRequest) {
	t.Helper()
	f, decision, handle := groupDisplayDecisionFixture(t)
	req := prepareGroupDisplayTestRequest(t, f, handle)
	iv, ciphertext, err := keepercrypto.SealAESGCM(rand.Reader, mustHex(t, f.v.GroupDEKHex), []byte("synthetic display boundary"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.IVB64 = base64.StdEncoding.EncodeToString(iv)
	req.CiphertextB64 = base64.StdEncoding.EncodeToString(ciphertext)
	prepared := HandleGroupDisplayPrepare(f.deps, payloadOf(t, req))
	if !prepared.Success {
		t.Fatal("display preparation failed")
	}
	p := prepared.Data.(proto.CurrentGroupDisplayPrepareResponseData)
	decision.Challenge, decision.GroupID, decision.DekVersion = p.Challenge, p.GroupID, p.DekVersion
	decision.GrantDigest, decision.OperationDigest, decision.FrameKeyDigest = p.GrantDigest, p.OperationDigest, p.FrameKeyDigest
	decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
	return f, proto.CurrentGroupDisplayExecuteRequest{Prepare: req, Decision: decision}
}

func TestGroupDisplayExecuteRefusesLocalInvalidationWithoutEnvelope(t *testing.T) {
	for _, name := range []string{"logout", "new binding", "expired decision", "purged challenge"} {
		t.Run(name, func(t *testing.T) {
			f, req := preparedDisplayExecution(t)
			switch name {
			case "logout":
				if _, _, err := keychain.SignOutAccountBinding(f.store); err != nil {
					t.Fatal(err)
				}
			case "new binding":
				if _, _, err := keychain.SetAccountBinding(f.store, f.v.AccountID, "alice", true); err != nil {
					t.Fatal(err)
				}
			case "expired decision":
				f.clock.advance(9)
			case "purged challenge":
				f.deps.GroupDisplayChallenges.PurgeHandle(req.Prepare.GroupHandle)
			}
			resp := HandleGroupDisplayExecute(f.deps, payloadOf(t, req))
			if resp.Success || resp.Data != nil {
				t.Fatal("invalidated display returned an envelope")
			}
			if f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 0 {
				t.Fatal("invalidated display wrote clipboard")
			}
		})
	}
}

type displayExpiryReader struct {
	expire   func()
	onlySeal bool
}

func (r *displayExpiryReader) Read(p []byte) (int, error) {
	if r.expire != nil && (!r.onlySeal || len(p) == 12) {
		expire := r.expire
		r.expire = nil
		expire()
	}
	return rand.Read(p)
}

func TestGroupDisplayExecuteRefusesDecisionExpiringDuringFrameKeyGeneration(t *testing.T) {
	f, req := preparedDisplayExecution(t)
	// Key generation happens after decision verification. A scheduler or entropy
	// delay must not turn that earlier check into permission after expiry.
	f.deps.Rand = &displayExpiryReader{expire: func() { f.clock.advance(9) }}
	resp := HandleGroupDisplayExecute(f.deps, payloadOf(t, req))
	if resp.Success || resp.Data != nil {
		t.Fatal("decision expired before decryption but an envelope was returned")
	}
	if f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 0 {
		t.Fatal("expired display wrote clipboard")
	}
}

func TestGroupDisplayExecuteRefusesDecisionExpiringDuringEnvelopeSealing(t *testing.T) {
	f, req := preparedDisplayExecution(t)
	f.deps.Rand = &displayExpiryReader{onlySeal: true, expire: func() { f.clock.advance(9) }}
	resp := HandleGroupDisplayExecute(f.deps, payloadOf(t, req))
	if resp.Success || resp.Data != nil {
		t.Fatal("expired decision released a frame envelope")
	}
}

func preparedAuditDisplayExecution(t *testing.T) (*auditFixture, proto.AuditGroupDisplayExecuteRequest) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.GroupDisplayChallenges = NewGroupDisplayChallengeStore()
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	frameKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	frameSPKI, err := x509.MarshalPKIXPublicKey(&frameKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := f.permit(t, nil)
	boundIV, boundCT := f.boundAuditToken(t, "never")
	req := proto.AuditGroupDisplayPrepareRequest{
		GroupHandle: f.handle, Token: "audit-token", IVB64: base64.StdEncoding.EncodeToString(boundIV),
		CiphertextB64: base64.StdEncoding.EncodeToString(boundCT), TokenExpiry: "never",
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(frameSPKI),
		TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
		OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table), Permit: permit,
	}
	prepared := HandleAuditGroupDisplayPrepare(f.deps, payloadOf(t, req))
	if !prepared.Success {
		t.Fatalf("prepare: %s", prepared.Error)
	}
	p := prepared.Data.(proto.AuditGroupDisplayPrepareResponseData)
	decision := proto.AuditGroupDisplayDecision{CurrentGroupDisplayDecision: proto.CurrentGroupDisplayDecision{
		Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: deviceID,
		TokenID: req.TokenID, SessionIssuedAtNanos: 123456789,
		GroupID: p.GroupID, DekVersion: p.DekVersion, GrantDigest: p.GrantDigest,
		OperationDigest: p.OperationDigest, FrameKeyDigest: p.FrameKeyDigest,
		IssuedAt: f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9, ServerKeyVersion: 1,
	}, TableID: p.TableID, TableDigest: p.TableDigest}
	decision.Signature = f.sign(t, proto.AuditGroupDisplayDecisionCanonical(decision))

	return f, proto.AuditGroupDisplayExecuteRequest{Prepare: req, Decision: decision}
}

func TestAuditGroupDisplayExecuteRefusesDecisionExpiringDuringCrypto(t *testing.T) {
	for _, onlySeal := range []bool{false, true} {
		name := "key generation"
		if onlySeal {
			name = "envelope sealing"
		}
		t.Run(name, func(t *testing.T) {
			f, req := preparedAuditDisplayExecution(t)
			f.deps.Rand = &displayExpiryReader{onlySeal: onlySeal, expire: func() { f.clock.advance(9) }}
			resp := HandleAuditGroupDisplayExecute(f.deps, payloadOf(t, req))
			if resp.Success || resp.Data != nil {
				t.Fatal("expired audit decision released a frame envelope")
			}
			if f.deps.Clipboard.(*clipboard.MemoryClipboard).WriteCount() != 0 {
				t.Fatal("expired audit display wrote clipboard")
			}
		})
	}
}
