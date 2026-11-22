package handlers

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// archiveSourcePEM returns the org's active archive private key PEM.
func (f *splitFixture) archiveSourcePEM(t *testing.T, org string) string {
	t.Helper()
	pem, err := keychain.OrgArchiveActiveSlot(org).GetPrivate(f.store)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// rotationRun is one combine_to_staged request whose shares reconstruct
// sourcePEM, wrapped to the org's live session key (begun when absent).
type rotationRun struct {
	f   *splitFixture
	req proto.ArchiveRotationRequest
}

func newRotationRun(t *testing.T, f *splitFixture, split proto.ArchiveKeySplitRequest, sourcePEM string) *rotationRun {
	t.Helper()
	public, err := keychain.GetArchiveSessionPublicKey(f.store, split.OrgID)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		public = beginOrgSession(t, f.deps, split.OrgID).SessionPublicKey
	} else if err != nil {
		t.Fatal(err)
	}
	sessionPub, err := crypto.ParsePublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := crypto.SplitSecret([]byte(sourcePEM), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveRotationRequest{OrgID: split.OrgID, OperationID: split.OperationID, SessionID: splitTestOther, ConfigDigest: split.ConfigDigest, Grants: []proto.RotationGrant{}}
	for i, s := range shares {
		wk, ct, err := crypto.HybridWrap(sessionPub, crypto.SerializeShare(s))
		if err != nil {
			t.Fatal(err)
		}
		req.Shares = append(req.Shares, proto.RotationShare{AccountID: splitTestRecipientAccounts[i], Index: i + 1, WrappedKey: wk, Ciphertext: ct})
	}
	return &rotationRun{f: f, req: req}
}

// addGrant appends one grant whose DEK is wrapped to sourcePublic.
func (r *rotationRun) addGrant(t *testing.T, sourcePublic string) {
	t.Helper()
	group := sessionGrantContext(r.req.OrgID)
	pub, err := crypto.ParsePublicKey(sourcePublic)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := wrapGrant(pub, sessionTestDEK(), group)
	if err != nil {
		t.Fatal(err)
	}
	r.req.Grants = append(r.req.Grants, proto.RotationGrant{ID: splitTestOperation, GroupID: group.GroupID, Version: group.DekVersion, Policy: group.Policy, Wrapped: base64.StdEncoding.EncodeToString(cipher)})
}

// decision prepares the request and returns a signed rotation decision.
func (r *rotationRun) decision(t *testing.T) proto.RotationDecision {
	t.Helper()
	f := r.f
	p := HandleArchiveRotationPrepare(f.deps, proto.ArchiveRotationPrepare{Request: r.req, TokenID: splitTestToken, SessionStart: 123})
	if !p.Success {
		t.Fatal("rotation prepare", p.ErrorCode)
	}
	ready := p.Data.(proto.RotationPrepared)
	d, err := r.req.Commitment(f.v.AccountID, ready.TargetSPKI)
	if err != nil {
		t.Fatal(err)
	}
	d.Challenge, d.DeviceID, d.TokenID, d.SessionStart = ready.Challenge, splitTestDevice, splitTestToken, 123
	d.IssuedAt = f.deps.Now().Unix()
	d.ExpiresAt = d.IssuedAt + 10
	d.Version = 1
	d.Signature = f.sign(t, d.Canonical())
	return d
}

func (r *rotationRun) run(d proto.RotationDecision) proto.BaseResponse {
	return HandleArchiveQuorumCombineToStaged(r.f.deps, proto.ArchiveRotationExecute{Request: r.req, Decision: d})
}

// finalizationReceipt is the signed v2 finalization receipt matching the
// split of req with the returned shares; edit changes it before signing.
func (f *splitFixture) finalizationReceipt(t *testing.T, req proto.ArchiveKeySplitRequest, shares []proto.WrappedShare, edit func(*proto.ArchiveSplitFinalizationReceipt)) proto.ArchiveSplitFinalizationReceipt {
	t.Helper()
	d := req.ReconfigurationDecision
	r := proto.ArchiveSplitFinalizationReceipt{Kind: "reconfiguration", OperationID: req.OperationID, OrgID: req.OrgID, ArchiveKeySPKIFingerprint: d.ActiveKeySPKIFingerprint, TargetKeySPKIFingerprint: d.TargetKeySPKIFingerprint, SourceConfigDigest: d.SourceConfigDigest, ConfigDigest: d.ConfigDigest, SharesDigest: proto.ArchiveSplitSharesDigest(shares), GrantsDigest: strings.Repeat("f", 64), FinalizedAt: 500, ServerKeyVersion: 1}
	if edit != nil {
		edit(&r)
	}
	r.Signature = f.sign(t, proto.ArchiveSplitFinalizationReceiptCanonical(r))
	return r
}

func (f *splitFixture) finalize(r proto.ArchiveSplitFinalizationReceipt) proto.BaseResponse {
	return HandleArchiveSplitFinalize(f.deps, proto.ArchiveSplitFinalizeRequest{OrgID: r.OrgID, Receipt: &r})
}
