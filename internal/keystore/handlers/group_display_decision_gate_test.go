package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func groupDisplayDecisionFixture(t *testing.T) (*auditFixture, proto.CurrentGroupDisplayDecision, string) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.GroupDisplayChallenges = NewGroupDisplayChallengeStore()
	f.deps.DisplayTokens = testDisplayTokens{}
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	gc := legacyContext(f.v)
	handle := f.openWith(t, f.wrapToMe(t, f.pubPEM, gc), gc)
	label, err := f.deps.GroupSessions.LabelOf(handle)
	if err != nil {
		t.Fatal(err)
	}
	binding, found, err := keychain.GetAccountBinding(f.store)
	if err != nil || !found {
		t.Fatalf("account binding: found=%t err=%v", found, err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	operationDigest := sha256.Sum256([]byte("one ciphertext-only display operation"))
	frameDigest := sha256.Sum256([]byte("one frame public key"))
	decision := proto.CurrentGroupDisplayDecision{
		Challenge: challenge, AccountID: f.v.AccountID, DeviceID: deviceID,
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123456789,
		GroupID: gc.GroupID, DekVersion: gc.DekVersion,
		GrantDigest:     hex.EncodeToString(label.GrantDigest[:]),
		OperationDigest: hex.EncodeToString(operationDigest[:]),
		FrameKeyDigest:  hex.EncodeToString(frameDigest[:]),
		IssuedAt:        f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9,
		ServerKeyVersion: 1,
	}
	context := groupDisplayContext{
		groupHandle: handle, accountID: decision.AccountID, deviceID: decision.DeviceID,
		tokenID: decision.TokenID, sessionStartNanos: decision.SessionIssuedAtNanos,
		bindingGeneration: binding.Generation, operationDigest: operationDigest,
		frameKeyDigest: frameDigest,
	}
	if err := f.deps.GroupDisplayChallenges.Put(challenge, context, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
	return f, decision, handle
}

func TestGroupDisplayDecisionGateRequiresExactSignedLiveBindingAndConsumesOnce(t *testing.T) {
	f, decision, handle := groupDisplayDecisionFixture(t)
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err != nil {
		t.Fatalf("valid decision refused: %v", err)
	}
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err == nil {
		t.Fatal("decision replay accepted")
	}
}

func TestGroupDisplayDecisionGateRefusesChangedSignedFieldsAndKeepsChallenge(t *testing.T) {
	for name, change := range map[string]func(*proto.CurrentGroupDisplayDecision){
		"account": func(d *proto.CurrentGroupDisplayDecision) { d.AccountID = "77777777-7777-4777-8777-777777777777" },
		"device":  func(d *proto.CurrentGroupDisplayDecision) { d.DeviceID = "77777777-7777-4777-8777-777777777777" },
		"token":   func(d *proto.CurrentGroupDisplayDecision) { d.TokenID = "77777777-7777-4777-8777-777777777777" },
		"session": func(d *proto.CurrentGroupDisplayDecision) { d.SessionIssuedAtNanos++ },
		"group":   func(d *proto.CurrentGroupDisplayDecision) { d.GroupID = "77777777-7777-4777-8777-777777777777" },
		"version": func(d *proto.CurrentGroupDisplayDecision) { d.DekVersion++ },
		"grant": func(d *proto.CurrentGroupDisplayDecision) {
			d.GrantDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
		},
		"operation": func(d *proto.CurrentGroupDisplayDecision) {
			d.OperationDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
		},
		"frame": func(d *proto.CurrentGroupDisplayDecision) {
			d.FrameKeyDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
		},
		"expiry": func(d *proto.CurrentGroupDisplayDecision) { d.IssuedAt += 7; d.ExpiresAt += 7 },
	} {
		t.Run(name, func(t *testing.T) {
			f, decision, handle := groupDisplayDecisionFixture(t)
			change(&decision)
			decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
			if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err == nil {
				t.Fatal("changed signed decision accepted")
			}
			if _, pending := f.deps.GroupDisplayChallenges.Peek(decision.Challenge, f.clock.now()); !pending {
				t.Fatal("invalid decision consumed the challenge")
			}
		})
	}
}

func TestGroupDisplayDecisionGateRefusesInvalidSignatureAndLocalChange(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *auditFixture, *proto.CurrentGroupDisplayDecision){
		"wrong signature": func(t *testing.T, f *auditFixture, d *proto.CurrentGroupDisplayDecision) {
			d.Signature = f.sign(t, "another decision")
		},
		"new login generation": func(t *testing.T, f *auditFixture, _ *proto.CurrentGroupDisplayDecision) {
			if _, _, err := keychain.SetAccountBinding(f.store, f.v.AccountID, "alice", true); err != nil {
				t.Fatal(err)
			}
		},
		"signed out": func(t *testing.T, f *auditFixture, _ *proto.CurrentGroupDisplayDecision) {
			if _, _, err := keychain.SignOutAccountBinding(f.store); err != nil {
				t.Fatal(err)
			}
		},
		"changed device": func(t *testing.T, f *auditFixture, _ *proto.CurrentGroupDisplayDecision) {
			if err := f.store.Set(config.Service, config.DeviceID, "77777777-7777-4777-8777-777777777777"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, decision, handle := groupDisplayDecisionFixture(t)
			change(t, f, &decision)
			if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err == nil {
				t.Fatal("invalid or stale local state accepted")
			}
			if _, pending := f.deps.GroupDisplayChallenges.Peek(decision.Challenge, f.clock.now()); !pending {
				t.Fatal("refused decision consumed the challenge")
			}
		})
	}
}

func TestGroupDisplayDecisionGateRefusesExpiredResponseAndChallenge(t *testing.T) {
	for _, delay := range []int64{9, 10} {
		t.Run(strconv.FormatInt(delay, 10), func(t *testing.T) {
			f, decision, handle := groupDisplayDecisionFixture(t)
			f.clock.advance(delay)
			if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, handle); err == nil {
				t.Fatal("expired display decision or challenge accepted")
			}
		})
	}
}

func TestGroupDisplayDecisionGateRefusesAnotherHandleAndAuditPolicy(t *testing.T) {
	f, decision, handle := groupDisplayDecisionFixture(t)
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, f.handle); err == nil {
		t.Fatal("decision for another Group handle accepted")
	}
	if _, pending := f.deps.GroupDisplayChallenges.Peek(decision.Challenge, f.clock.now()); !pending {
		t.Fatal("wrong handle consumed the challenge")
	}
	f.deps.GroupDisplayChallenges.PurgeHandle(handle)
	auditLabel, err := f.deps.GroupSessions.LabelOf(f.handle)
	if err != nil {
		t.Fatal(err)
	}
	decision.GrantDigest = hex.EncodeToString(auditLabel.GrantDigest[:])
	decision.Signature = f.sign(t, proto.CurrentGroupDisplayDecisionCanonical(decision))
	binding, found, err := keychain.GetAccountBinding(f.store)
	if err != nil || !found {
		t.Fatalf("account binding: found=%t err=%v", found, err)
	}
	context := groupDisplayContext{
		groupHandle: f.handle, accountID: decision.AccountID, deviceID: decision.DeviceID,
		tokenID: decision.TokenID, sessionStartNanos: decision.SessionIssuedAtNanos,
		bindingGeneration: binding.Generation,
		operationDigest:   decodedGroupDisplayDigest(decision.OperationDigest),
		frameKeyDigest:    decodedGroupDisplayDigest(decision.FrameKeyDigest),
	}
	if err := f.deps.GroupDisplayChallenges.Put(decision.Challenge, context, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyAndConsumeCurrentGroupDisplayDecision(f.deps, decision, f.handle); err == nil {
		t.Fatal("non-audit decision accepted an audit-only handle")
	}
}
