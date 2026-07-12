// archive_quorum_test.go — org archive-key admin quorum (Shamir N-of-M) tests.
//
// Coverage:
//  1. split → session → per-admin rewrap → combine round-trip recovers the OLD
//     Group DEK for a target member, and split deletes the archive private key.
//  2. below-threshold combine fails (the reconstructed key does not parse) —
//     no silent wrong-DEK leak.
//  3. no raw key / DEK material appears in the combine response.
//  4. split with no archive key → not_found; share rewrap round-trips through
//     an admin's own slot; session begin/end lifecycle.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// genAdminKeys returns m fresh RSA keypairs and their public-key PEMs.
func genAdminKeys(t *testing.T, m int) ([]*crypto.KeyPair, []string) {
	t.Helper()
	kps := make([]*crypto.KeyPair, m)
	pems := make([]string, m)
	for i := range kps {
		kp, err := crypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair admin %d: %v", i, err)
		}
		kps[i] = kp
		pems[i] = kp.PublicKey
	}
	return kps, pems
}

// adminRewrapShare simulates an approving admin: unwrap the hybrid share with
// their account archive private key, then re-wrap it to the session public key.
func adminRewrapShare(t *testing.T, adminKP *crypto.KeyPair, share proto.WrappedShare, sessionPubPEM string) proto.RewrappedShareInput {
	t.Helper()
	adminPriv, err := crypto.ParsePrivateKey(adminKP.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey admin: %v", err)
	}
	raw, err := crypto.HybridUnwrap(adminPriv, share.WrappedKey, share.Ciphertext)
	if err != nil {
		t.Fatalf("admin HybridUnwrap: %v", err)
	}
	sessionPub, err := crypto.ParsePublicKey(sessionPubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey session: %v", err)
	}
	wk, ct, err := crypto.HybridWrap(sessionPub, raw)
	if err != nil {
		t.Fatalf("admin HybridWrap to session: %v", err)
	}
	return proto.RewrappedShareInput{WrappedKey: wk, Ciphertext: ct}
}

func TestArchiveQuorum_FullFlowRoundTrip(t *testing.T) {
	deps, _, store := newTestDeps(t) // coordinator device

	archiveKP, _ := crypto.GenerateRSAKeyPair()
	if err := keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey); err != nil {
		t.Fatalf("SaveArchivePrivateKey: %v", err)
	}
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)

	const total, threshold = 5, 3
	adminKPs, adminPems := genAdminKeys(t, total)

	// 1) split → M shares, archive private key deleted.
	splitResp := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{
		ThresholdN:          threshold,
		RecipientPublicKeys: adminPems,
	})
	if !splitResp.Success {
		t.Fatalf("split failed: %s", splitResp.Error)
	}
	splitData := splitResp.Data.(proto.ArchiveKeySplitResponseData)
	if len(splitData.Shares) != total {
		t.Fatalf("got %d shares, want %d", len(splitData.Shares), total)
	}
	if pk, _ := keychain.GetArchivePrivateKey(store); pk != "" {
		t.Fatal("archive private key must be deleted after split")
	}
	// public key must be preserved.
	if pub, _ := keychain.GetArchivePublicKey(store); pub == "" {
		t.Fatal("archive public key must be preserved after split")
	}

	// 2) coordinator opens a recovery session.
	sessResp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{})
	if !sessResp.Success {
		t.Fatalf("session begin failed: %s", sessResp.Error)
	}
	sessionPubPEM := sessResp.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey

	// 3) threshold admins re-wrap their shares to the session key.
	rewrapped := make([]proto.RewrappedShareInput, 0, threshold)
	for i := 0; i < threshold; i++ {
		rewrapped = append(rewrapped, adminRewrapShare(t, adminKPs[i], splitData.Shares[i], sessionPubPEM))
	}

	// 4) an OLD Group DEK wrapped to the archive public key (org_owner_archive grant).
	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0xC0 + i)
	}
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrappedOld, _ := crypto.EncryptData(archivePub, groupDEK)

	// 5) target member.
	memberKP, _ := crypto.GenerateRSAKeyPair()

	// 6) combine + re-grant.
	combResp := HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares:     rewrapped,
		WrappedOldDEKB64:    base64.StdEncoding.EncodeToString(wrappedOld),
		RecipientPublicKeys: []string{memberKP.PublicKey},
	})
	if !combResp.Success {
		t.Fatalf("combine failed: %s", combResp.Error)
	}
	combData := combResp.Data.(proto.ArchiveQuorumCombineAndRewrapResponseData)
	if len(combData.Grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(combData.Grants))
	}

	// re-granted DEK must decrypt to the original with the member key.
	memberPriv, _ := crypto.ParsePrivateKey(memberKP.PrivateKey)
	enc, err := base64.StdEncoding.DecodeString(combData.Grants[0].EncryptedGroupDEKB64)
	if err != nil {
		t.Fatalf("decode grant: %v", err)
	}
	dec, err := crypto.DecryptData(memberPriv, enc)
	if err != nil {
		t.Fatalf("member DecryptData: %v", err)
	}
	if len(dec) != 32 {
		t.Fatalf("recovered DEK length = %d, want 32", len(dec))
	}
	for i := range groupDEK {
		if dec[i] != groupDEK[i] {
			t.Fatalf("recovered DEK[%d]=%#x want %#x — quorum reconstruction corrupted the DEK", i, dec[i], groupDEK[i])
		}
	}
}

func TestArchiveQuorum_BelowThresholdCombineFails(t *testing.T) {
	deps, _, store := newTestDeps(t)

	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)

	const total, threshold = 5, 3
	adminKPs, adminPems := genAdminKeys(t, total)

	splitData := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{
		ThresholdN: threshold, RecipientPublicKeys: adminPems,
	}).Data.(proto.ArchiveKeySplitResponseData)

	sessionPubPEM := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{}).
		Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey

	// Only threshold-1 = 2 shares (passes the >=2 protocol floor but is below
	// the cryptographic threshold).
	rewrapped := []proto.RewrappedShareInput{
		adminRewrapShare(t, adminKPs[0], splitData.Shares[0], sessionPubPEM),
		adminRewrapShare(t, adminKPs[1], splitData.Shares[1], sessionPubPEM),
	}

	groupDEK := make([]byte, 32)
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrappedOld, _ := crypto.EncryptData(archivePub, groupDEK)
	memberKP, _ := crypto.GenerateRSAKeyPair()

	resp := HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares:     rewrapped,
		WrappedOldDEKB64:    base64.StdEncoding.EncodeToString(wrappedOld),
		RecipientPublicKeys: []string{memberKP.PublicKey},
	})
	if resp.Success {
		t.Fatal("combine with below-threshold shares must fail, not silently reconstruct")
	}
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Errorf("expected crypto_failure, got %q", resp.ErrorCode)
	}
}

func TestArchiveQuorum_CombineNoRawInResponse(t *testing.T) {
	deps, _, store := newTestDeps(t)

	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)

	const total, threshold = 3, 2
	adminKPs, adminPems := genAdminKeys(t, total)
	splitData := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{
		ThresholdN: threshold, RecipientPublicKeys: adminPems,
	}).Data.(proto.ArchiveKeySplitResponseData)
	sessionPubPEM := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{}).
		Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey

	rewrapped := []proto.RewrappedShareInput{
		adminRewrapShare(t, adminKPs[0], splitData.Shares[0], sessionPubPEM),
		adminRewrapShare(t, adminKPs[1], splitData.Shares[1], sessionPubPEM),
	}

	groupDEK := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
	}
	rawB64 := base64.StdEncoding.EncodeToString(groupDEK)
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrappedOld, _ := crypto.EncryptData(archivePub, groupDEK)
	memberKP, _ := crypto.GenerateRSAKeyPair()

	resp := HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares:     rewrapped,
		WrappedOldDEKB64:    base64.StdEncoding.EncodeToString(wrappedOld),
		RecipientPublicKeys: []string{memberKP.PublicKey},
	})
	if !resp.Success {
		t.Fatalf("combine failed: %s", resp.Error)
	}
	jsonBytes, _ := json.Marshal(resp)
	if strings.Contains(string(jsonBytes), rawB64) {
		t.Errorf("raw group DEK leaked into response")
	}
	if strings.Contains(strings.ToUpper(string(jsonBytes)), "DEADBEEF") {
		t.Errorf("raw group DEK hex pattern leaked into response")
	}
	// The reconstructed archive private key PEM must never appear either.
	if strings.Contains(string(jsonBytes), "PRIVATE KEY") {
		t.Errorf("reconstructed private key material leaked into response")
	}
}

func TestArchiveQuorum_SplitMissingArchiveKey(t *testing.T) {
	deps, _, _ := newTestDeps(t) // no archive key stored
	_, adminPems := genAdminKeys(t, 3)
	resp := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{
		ThresholdN: 2, RecipientPublicKeys: adminPems,
	})
	if resp.Success {
		t.Fatal("split with no archive key must fail")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Errorf("expected not_found, got %q", resp.ErrorCode)
	}
}

// HandleArchiveShareRewrap must round-trip through an admin's own archive slot:
// a share wrapped to the admin key becomes a share wrapped to the session key
// whose plaintext is unchanged.
func TestArchiveQuorum_ShareRewrapHandler(t *testing.T) {
	adminDeps, _, adminStore := newTestDeps(t)

	adminKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(adminStore, adminKP.PrivateKey)
	adminPub, _ := crypto.ParsePublicKey(adminKP.PublicKey)

	sessionKP, _ := crypto.GenerateRSAKeyPair()

	shareBytes := []byte("serialized-shamir-share-bytes-stand-in-0123456789")
	wk, ct, _ := crypto.HybridWrap(adminPub, shareBytes)

	resp := HandleArchiveShareRewrap(adminDeps, proto.ArchiveShareRewrapRequest{
		WrappedKey:       wk,
		Ciphertext:       ct,
		SessionPublicKey: sessionKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("share rewrap failed: %s", resp.Error)
	}
	out := resp.Data.(proto.ArchiveShareRewrapResponseData)

	sessionPriv, _ := crypto.ParsePrivateKey(sessionKP.PrivateKey)
	got, err := crypto.HybridUnwrap(sessionPriv, out.WrappedKey, out.Ciphertext)
	if err != nil {
		t.Fatalf("session HybridUnwrap: %v", err)
	}
	if string(got) != string(shareBytes) {
		t.Fatalf("rewrapped share plaintext changed")
	}
}

func TestArchiveQuorum_SessionLifecycle(t *testing.T) {
	deps, _, store := newTestDeps(t)

	// end with no session → ended=false, idempotent.
	end := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{})
	if !end.Success || end.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatalf("end with no session should succeed with ended=false")
	}

	begin := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{})
	if !begin.Success {
		t.Fatalf("session begin failed: %s", begin.Error)
	}
	if priv, _ := keychain.GetArchiveSessionPrivateKey(store); priv == "" {
		t.Fatal("session private key should be stored after begin")
	}

	end2 := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{})
	if !end2.Success || !end2.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatal("end after begin should report ended=true")
	}
	if priv, _ := keychain.GetArchiveSessionPrivateKey(store); priv != "" {
		t.Fatal("session private key should be gone after end")
	}
}
