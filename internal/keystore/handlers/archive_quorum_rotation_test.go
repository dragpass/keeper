package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"strings"
	"testing"
)

func TestRotationToStagedUsesSignedRowsAndLocalTarget(t *testing.T) {
	f := newSplitFixture(t)
	f.deps.ArchiveRotationChallenges = NewArchiveShareChallengeStore()
	split, target := f.authorizeReconfiguration(t)
	if res := HandleArchiveKeySplit(f.deps, split); !res.Success {
		t.Fatal(res.ErrorCode)
	}
	source := keychain.OrgArchiveActiveSlot(split.OrgID)
	priv, err := source.GetPrivate(f.store)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := crypto.SplitSecret([]byte(priv), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.DeletePrivate(f.store); err != nil {
		t.Fatal(err)
	}
	session := beginOrgSession(t, f.deps, split.OrgID)
	sessionPub, err := crypto.ParsePublicKey(session.SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveRotationRequest{OrgID: split.OrgID, OperationID: split.OperationID, SessionID: splitTestOther, ConfigDigest: split.ConfigDigest}
	for i, s := range sh {
		wk, ct, err := crypto.HybridWrap(sessionPub, crypto.SerializeShare(s))
		if err != nil {
			t.Fatal(err)
		}
		req.Shares = append(req.Shares, proto.RotationShare{AccountID: splitTestRecipientAccounts[i], Index: i + 1, WrappedKey: wk, Ciphertext: ct})
	}
	group := sessionGrantContext(split.OrgID)
	oldPub, _ := crypto.ParsePublicKey(f.archive)
	cipher, err := wrapGrant(oldPub, sessionTestDEK(), group)
	if err != nil {
		t.Fatal(err)
	}
	req.Grants = []proto.RotationGrant{{ID: splitTestOperation, GroupID: group.GroupID, Version: group.DekVersion, Policy: group.Policy, Wrapped: base64.StdEncoding.EncodeToString(cipher)}}
	get := func() proto.RotationDecision {
		p := HandleArchiveRotationPrepare(f.deps, proto.ArchiveRotationPrepare{Request: req, TokenID: splitTestToken, SessionStart: 123})
		if !p.Success {
			t.Fatal("prepare", p.ErrorCode)
		}
		ready := p.Data.(proto.RotationPrepared)
		d, err := req.Commitment(f.v.AccountID, ready.TargetSPKI)
		if err != nil {
			t.Fatal(err)
		}
		if d.RequestDigest != ready.RequestDigest {
			t.Fatal("commitment mismatch")
		}
		d.Challenge = ready.Challenge
		d.DeviceID = splitTestDevice
		d.TokenID = splitTestToken
		d.SessionStart = 123
		d.IssuedAt = f.deps.Now().Unix()
		d.ExpiresAt = d.IssuedAt + 10
		d.Version = 1
		d.Signature = f.sign(t, d.Canonical())
		return d
	}
	run := func(d proto.RotationDecision) proto.BaseResponse {
		return HandleArchiveQuorumCombineToStaged(f.deps, proto.ArchiveRotationExecute{Request: req, Decision: d})
	}
	d := get()
	bad := d
	bad.Signature = "AAAA"
	f.probe.private[config.OrgArchiveSessionPrivateKeyPrefix+split.OrgID] = true
	f.resetProbe()
	if r := run(bad); r.Success || r.Data != nil || f.probe.privateReads != 0 {
		t.Fatal("invalid decision reached secret or output")
	}
	r := run(d)
	if !r.Success {
		t.Fatal("execute", r.ErrorCode)
	}
	if run(d).Success {
		t.Fatal("replayed decision")
	}
	outputs := r.Data.(proto.RotationOutputs).Grants
	if len(outputs) != 1 || outputs[0].Fingerprint != target.Fingerprint {
		t.Fatal("wrong recipient")
	}
	targetPEM, err := keychain.OrgArchiveReconfigurationSlot(split.OrgID).GetPrivate(f.store)
	if err != nil {
		t.Fatal(err)
	}
	targetPriv, _ := crypto.ParsePrivateKey(targetPEM)
	enc, _ := base64.StdEncoding.DecodeString(outputs[0].Wrapped)
	recovered, err := unwrapGrant(targetPriv, enc, group)
	if err != nil || !bytes.Equal(recovered, sessionTestDEK()) {
		t.Fatal("re-wrapped grant did not open with original policy")
	}
	late := get()
	f.probe.beforePrivateRead = func() { f.clock.advance(11) }
	if r := run(late); r.Success || r.Data != nil {
		t.Fatal("expired output")
	}
}

func TestSessionKeyProofMustMatchOwnedLiveSessionAndOperation(t *testing.T) {
	f := newSplitFixture(t)
	split, _ := f.authorizeReconfiguration(t)
	if r := HandleArchiveKeySplit(f.deps, split); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	session := beginOrgSession(t, f.deps, split.OrgID)
	fp, err := crypto.RewrapKeyFingerprint(session.SessionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	generated := HandleRequestKeyGenerate(f.deps, proto.RequestKeyGenerateRequest{})
	if !generated.Success {
		t.Fatal(generated.ErrorCode)
	}
	req := proto.ArchiveReconfigurationSessionKeyProof{OrgID: split.OrgID, OperationID: split.OperationID, SessionID: splitTestOther, ConfigDigest: split.ConfigDigest, SessionSPKI: fp}
	sign := func(req proto.ArchiveReconfigurationSessionKeyProof) proto.BaseResponse {
		return HandleArchiveReconfigurationSessionKeyProof(f.deps, req)
	}
	bad := req
	bad.SessionSPKI = strings.Repeat("0", 64)
	if r := sign(bad); r.Success || r.Data != nil {
		t.Fatal("signed a mismatched session")
	}
	r := sign(req)
	if !r.Success {
		t.Fatal(r.ErrorCode)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Data.(proto.ArchiveSessionKeySignature).Signature)
	pub64, err2 := keychain.GetRequestSigningPublicKey(f.store)
	pub, err3 := base64.StdEncoding.DecodeString(pub64)
	if err != nil || err2 != nil || err3 != nil || !ed25519.Verify(pub, []byte(req.Canonical(f.v.AccountID, splitTestDevice, fp)), sig) {
		t.Fatal("invalid proof signature")
	}
	if !sign(req).Success {
		t.Fatal("idempotent proof refused")
	}
	bad = req
	bad.SessionID = splitTestToken
	if r := sign(bad); r.Success || r.Data != nil {
		t.Fatal("signed another session for the same local key")
	}
}
