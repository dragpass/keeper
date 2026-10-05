// archive_key_org_test.go — org-scoped archive key rotation (0.0.58).
//
// Two orgs owned on one device used to share one archive keypair and one
// stage: beginning org B's rotation overwrote org A's stage, and committing
// either org wiped the key the other org's grants were wrapped to. With
// org_id each org stages and commits in its own slot, and the device-wide
// slots stay readable for keys and stages an older Keeper left behind.

package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	testOrgA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testOrgB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func wrapToArchive(t *testing.T, publicPEM string, dek []byte) string {
	t.Helper()
	pub, err := crypto.ParsePublicKey(publicPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	wrapped, err := crypto.EncryptData(pub, dek)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

// rewrapAndOpen re-grants a wrapped archive DEK to recipient and opens the
// result with its private key, returning the DEK.
func rewrapAndOpen(t *testing.T, deps Deps, orgID, wrapped string, recipient *crypto.KeyPair) []byte {
	t.Helper()
	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		OrgID:                orgID,
		WrappedForArchiveB64: wrapped,
		RecipientPublicKey:   recipient.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("rewrap (org %q): %s", orgID, resp.Error)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp.Data.(proto.ArchiveUnwrapAndRewrapResponseData).EncryptedForOtherB64)
	priv, err := crypto.ParsePrivateKey(recipient.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	dek, err := crypto.DecryptData(priv, raw)
	if err != nil {
		t.Fatalf("open re-grant: %v", err)
	}
	return dek
}

func beginOrg(t *testing.T, deps Deps, orgID string) proto.ArchiveKeyRotateBeginResponseData {
	t.Helper()
	resp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{OrgID: orgID})
	if !resp.Success {
		t.Fatalf("begin %s: %s", orgID, resp.Error)
	}
	return resp.Data.(proto.ArchiveKeyRotateBeginResponseData)
}

// The #278 limit: org A's rotation has an unknown outcome (staged, maybe
// submitted) when org B rotates. A's stage must survive B's begin and commit,
// and A's commit must still promote A's own staged key; neither commit may
// wipe the key the other org's grants are wrapped to.
func TestArchiveRotate_ConcurrentOrgsKeepTheirOwnStageAndKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	shared := seedActiveArchiveKey(t, deps) // both orgs registered this key
	dekA := make([]byte, 32)
	dekB := make([]byte, 32)
	for i := range dekA {
		dekA[i], dekB[i] = byte(i), byte(0x80+i)
	}
	grantA := wrapToArchive(t, shared.PublicKey, dekA)
	grantB := wrapToArchive(t, shared.PublicKey, dekB)

	stagedA := beginOrg(t, deps, testOrgA)
	if stagedA.Scope != keychain.ArchiveScopeOrg {
		t.Fatalf("org begin scope = %q", stagedA.Scope)
	}
	stagedB := beginOrg(t, deps, testOrgB)
	if stagedA.Fingerprint == stagedB.Fingerprint {
		t.Fatal("each org must stage its own key")
	}

	// A's re-grant to its stage, made with the shared key, as A's run did.
	regrantA := rewrapToStaged(t, deps, testOrgA, grantA, stagedA.PublicKey)

	// B finishes first.
	regrantB := rewrapToStaged(t, deps, testOrgB, grantB, stagedB.PublicKey)
	commitB := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgB, ExpectedFingerprint: stagedB.Fingerprint})
	if !commitB.Success {
		t.Fatalf("commit B: %s", commitB.Error)
	}

	// A's stage is still there, and the shared key still opens A's old grant.
	status := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: testOrgA})
	statusA := status.Data.(proto.ArchiveKeyStatusResponseData)
	if statusA.StagingFingerprint != stagedA.Fingerprint || statusA.Scope != keychain.ArchiveScopeDevice || statusA.Fingerprint != shared.Fingerprint {
		t.Fatalf("org A after B's commit: %+v", statusA)
	}
	recipient, _ := crypto.GenerateRSAKeyPair()
	if got := rewrapAndOpen(t, deps, testOrgA, grantA, recipient); string(got) != string(dekA) {
		t.Fatal("B's commit must not wipe the key A's grants are wrapped to")
	}

	commitA := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgA, ExpectedFingerprint: stagedA.Fingerprint})
	if !commitA.Success {
		t.Fatalf("commit A: %s", commitA.Error)
	}

	// Each org's re-granted DEK opens with its own new key only.
	if got := rewrapAndOpen(t, deps, testOrgA, regrantA, recipient); string(got) != string(dekA) {
		t.Fatal("A's re-grant must open with A's committed key")
	}
	if got := rewrapAndOpen(t, deps, testOrgB, regrantB, recipient); string(got) != string(dekB) {
		t.Fatal("B's re-grant must open with B's committed key")
	}
	for org, want := range map[string]string{testOrgA: stagedA.Fingerprint, testOrgB: stagedB.Fingerprint} {
		st := HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: org}).Data.(proto.ArchiveKeyStatusResponseData)
		if st.Fingerprint != want || st.Scope != keychain.ArchiveScopeOrg || st.StagingFingerprint != "" {
			t.Fatalf("org %s after both commits: %+v", org, st)
		}
	}
	// The device-wide key is kept for any other org still using it.
	if pub, _ := keychain.GetArchivePublicKey(deps.Store); pub != shared.PublicKey {
		t.Fatal("an org-scoped commit must not replace the device-wide key")
	}
}

func rewrapToStaged(t *testing.T, deps Deps, orgID, wrapped, stagedPEM string) string {
	t.Helper()
	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		OrgID:                orgID,
		WrappedForArchiveB64: wrapped,
		RecipientPublicKey:   stagedPEM,
	})
	if !resp.Success {
		t.Fatalf("rewrap to stage (%s): %s", orgID, resp.Error)
	}
	return resp.Data.(proto.ArchiveUnwrapAndRewrapResponseData).EncryptedForOtherB64
}

// A rotation an older Keeper began sits in the device-wide stage. After the
// upgrade, another org's begin and abort leave it alone, and the org it
// belongs to commits it by fingerprint into its own slot.
func TestArchiveRotate_LegacyStageSurvivesAndCommitsToTheOrg(t *testing.T) {
	deps, _, store := newTestDeps(t)
	shared := seedActiveArchiveKey(t, deps)
	legacy := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !legacy.Success {
		t.Fatalf("legacy begin: %s", legacy.Error)
	}
	legacyStage := legacy.Data.(proto.ArchiveKeyRotateBeginResponseData)
	if legacyStage.Scope != keychain.ArchiveScopeDevice {
		t.Fatalf("legacy begin scope = %q", legacyStage.Scope)
	}

	beginOrg(t, deps, testOrgB)
	if r := HandleArchiveKeyRotateAbort(deps, proto.ArchiveKeyRotateAbortRequest{OrgID: testOrgB}); !r.Success || !r.Data.(proto.ArchiveKeyRotateAbortResponseData).Aborted {
		t.Fatalf("abort B: %+v", r)
	}
	if pub, _ := keychain.OrgArchiveStagingSlot("").GetPublic(store); pub != legacyStage.PublicKey {
		t.Fatal("org B's begin and abort must not touch the device-wide stage")
	}

	// A wrong expected fingerprint changes nothing.
	wrong := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgA, ExpectedFingerprint: shared.Fingerprint})
	if wrong.Success || wrong.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("mismatched expected_fingerprint: %+v", wrong)
	}
	if pub, _ := keychain.OrgArchiveStagingSlot("").GetPublic(store); pub != legacyStage.PublicKey {
		t.Fatal("a refused commit must keep the stage")
	}

	commit := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgA, ExpectedFingerprint: legacyStage.Fingerprint})
	if !commit.Success {
		t.Fatalf("commit legacy stage for A: %s", commit.Error)
	}
	if got := commit.Data.(proto.ArchiveKeyRotateCommitResponseData); got.Scope != keychain.ArchiveScopeOrg || got.Fingerprint != legacyStage.Fingerprint {
		t.Fatalf("commit result: %+v", got)
	}
	if pub, _ := keychain.OrgArchiveActiveSlot(testOrgA).GetPublic(store); pub != legacyStage.PublicKey {
		t.Fatal("the legacy stage must become A's own active key")
	}
	if _, err := keychain.OrgArchiveStagingSlot("").GetPublic(store); err == nil {
		t.Fatal("the promoted legacy stage must be cleared")
	}
	if pub, _ := keychain.GetArchivePublicKey(store); pub != shared.PublicKey {
		t.Fatal("the device-wide key must stay for orgs still using it")
	}
}

// Requests without org_id keep the device-wide behavior.
func TestArchiveRotate_NoOrgIDUsesDeviceSlots(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveArchiveKey(t, deps)
	staged := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{}).Data.(proto.ArchiveKeyRotateBeginResponseData)
	commit := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{})
	if !commit.Success || commit.Data.(proto.ArchiveKeyRotateCommitResponseData).Scope != keychain.ArchiveScopeDevice {
		t.Fatalf("device commit: %+v", commit)
	}
	if pub, _ := keychain.GetArchivePublicKey(store); pub != staged.PublicKey {
		t.Fatal("device-wide commit must replace the device-wide key")
	}
}

func TestArchiveOrgID_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	seedActiveArchiveKey(t, deps)
	bad := "AAAAAAAA-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	responses := map[string]proto.BaseResponse{
		"status": HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: bad}),
		"begin":  HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{OrgID: "../x"}),
		"commit": HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: bad}),
		"commit_fp": HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{
			OrgID: testOrgA, ExpectedFingerprint: "XYZ",
		}),
		"abort": HandleArchiveKeyRotateAbort(deps, proto.ArchiveKeyRotateAbortRequest{OrgID: bad}),
	}
	for name, resp := range responses {
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Errorf("%s: want validation_error, got %+v", name, resp)
		}
	}
}

// A split names its org: it splits and wipes that org's own key, and the
// device-wide key other orgs use stays whole.
func TestArchiveSplit_OrgScopedWipesOnlyTheOrgKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	shared := seedActiveArchiveKey(t, deps)
	staged := beginOrg(t, deps, testOrgA)
	if r := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgA}); !r.Success {
		t.Fatalf("commit A: %s", r.Error)
	}
	_, adminPems := genAdminKeys(t, 3)
	split := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{OrgID: testOrgA, ThresholdN: 2, RecipientPublicKeys: adminPems})
	if !split.Success {
		t.Fatalf("split A: %s", split.Error)
	}
	if got := split.Data.(proto.ArchiveKeySplitResponseData).KeyFingerprint; got != staged.Fingerprint {
		t.Fatalf("split fingerprint = %s, want A's key %s", got, staged.Fingerprint)
	}
	if _, err := keychain.OrgArchiveActiveSlot(testOrgA).GetPrivate(store); err == nil {
		t.Fatal("A's private key must be wiped after split")
	}
	if priv, _ := keychain.GetArchivePrivateKey(store); priv == "" {
		t.Fatal("the device-wide private key must survive an org-scoped split")
	}
	// A second split of A finds A's slot without its private half and must
	// not fall through to the device-wide key.
	again := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{OrgID: testOrgA, ThresholdN: 2, RecipientPublicKeys: adminPems})
	if again.Success || again.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("second split of A: %+v", again)
	}
	if pub, _ := keychain.GetArchivePublicKey(store); pub != shared.PublicKey {
		t.Fatal("device-wide key changed")
	}
}
