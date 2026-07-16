// archive_key_rotate_test.go — same-device archive key rotation (staging slot)
// regression guard.
//
//  1. begin → commit happy path: a genuinely new key becomes active, the old
//     private key can no longer unwrap, and the staging slot is cleared.
//  2. begin → abort: active key untouched, staging cleared.
//  3. commit without begin → not_found.
//  4. begin without an active key → validation (first-time enable must go
//     through archive_key_generate).
//  5. repeated begin overwrites the abandoned staging (new fingerprint).
//  6. between begin and commit, archive_unwrap_and_rewrap still unwraps with
//     the OLD active key — the whole point of the staging design: existing
//     grants can be re-wrapped to the staged public key before commit.
//
// The staged/active private keys must never appear in a response
// serialization.

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

// seedActiveArchiveKey generates and stores an active archive keypair,
// returning the generate response meta.
func seedActiveArchiveKey(t *testing.T, deps Deps) proto.ArchiveKeyGenerateResponseData {
	t.Helper()
	resp := HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{})
	if !resp.Success {
		t.Fatalf("seed generate failed: %s", resp.Error)
	}
	data, ok := resp.Data.(proto.ArchiveKeyGenerateResponseData)
	if !ok {
		t.Fatalf("unexpected generate response type: %T", resp.Data)
	}
	return data
}

func TestHandleArchiveKeyRotate_BeginCommitHappyPath(t *testing.T) {
	deps, _, store := newTestDeps(t)
	active := seedActiveArchiveKey(t, deps)

	beginResp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !beginResp.Success {
		t.Fatalf("rotate begin failed: %s", beginResp.Error)
	}
	beginData, ok := beginResp.Data.(proto.ArchiveKeyRotateBeginResponseData)
	if !ok {
		t.Fatalf("unexpected begin response type: %T", beginResp.Data)
	}
	if beginData.PublicKey == "" || beginData.Fingerprint == "" {
		t.Fatalf("begin must return staged public key + fingerprint: %+v", beginData)
	}
	if beginData.Fingerprint == active.Fingerprint {
		t.Fatal("staged key must be genuinely new (fingerprint equals active)")
	}

	// The active slot is untouched until commit.
	if pub, err := keychain.GetArchivePublicKey(store); err != nil || pub != active.PublicKey {
		t.Fatalf("active public key must be untouched by begin: %v", err)
	}

	// The staged private key must never appear in the response serialization.
	raw, _ := json.Marshal(beginResp)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("begin response must not leak private material")
	}

	commitResp := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{})
	if !commitResp.Success {
		t.Fatalf("rotate commit failed: %s", commitResp.Error)
	}
	commitData, ok := commitResp.Data.(proto.ArchiveKeyRotateCommitResponseData)
	if !ok {
		t.Fatalf("unexpected commit response type: %T", commitResp.Data)
	}
	if commitData.Fingerprint != beginData.Fingerprint {
		t.Errorf("commit fingerprint = %q, want staged %q", commitData.Fingerprint, beginData.Fingerprint)
	}

	// Active slot now holds the staged key; staging is cleared.
	if pub, err := keychain.GetArchivePublicKey(store); err != nil || pub != beginData.PublicKey {
		t.Fatalf("active public key must be the staged key after commit: %v", err)
	}
	if staged, err := keychain.GetArchiveStagingPrivateKey(store); err == nil && staged != "" {
		t.Error("staging private slot must be cleared after commit")
	}

	// The old private key is gone: material wrapped to the OLD public key must
	// no longer unwrap via the composite action.
	oldPub, err := crypto.ParsePublicKey(active.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey (old active): %v", err)
	}
	dek := make([]byte, 32)
	wrappedToOld, err := crypto.EncryptData(oldPub, dek)
	if err != nil {
		t.Fatalf("EncryptData (old active): %v", err)
	}
	recipientKP, _ := crypto.GenerateRSAKeyPair()
	rewrapResp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrappedToOld),
		RecipientPublicKey:   recipientKP.PublicKey,
	})
	if rewrapResp.Success {
		t.Fatal("old-key-wrapped material must not unwrap after commit (old key wiped)")
	}
}

func TestHandleArchiveKeyRotate_BeginAbortKeepsActive(t *testing.T) {
	deps, _, store := newTestDeps(t)
	active := seedActiveArchiveKey(t, deps)

	beginResp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !beginResp.Success {
		t.Fatalf("rotate begin failed: %s", beginResp.Error)
	}

	abortResp := HandleArchiveKeyRotateAbort(deps, proto.ArchiveKeyRotateAbortRequest{})
	if !abortResp.Success {
		t.Fatalf("rotate abort failed: %s", abortResp.Error)
	}
	abortData, ok := abortResp.Data.(proto.ArchiveKeyRotateAbortResponseData)
	if !ok {
		t.Fatalf("unexpected abort response type: %T", abortResp.Data)
	}
	if !abortData.Aborted {
		t.Error("abort with staging present must report aborted=true")
	}

	if pub, err := keychain.GetArchivePublicKey(store); err != nil || pub != active.PublicKey {
		t.Fatalf("active key must survive abort: %v", err)
	}
	if staged, err := keychain.GetArchiveStagingPrivateKey(store); err == nil && staged != "" {
		t.Error("staging must be cleared after abort")
	}

	// Abort without staging is a no-op success.
	again := HandleArchiveKeyRotateAbort(deps, proto.ArchiveKeyRotateAbortRequest{})
	if !again.Success {
		t.Fatalf("abort without staging must succeed: %s", again.Error)
	}
	if data, _ := again.Data.(proto.ArchiveKeyRotateAbortResponseData); data.Aborted {
		t.Error("abort without staging must report aborted=false")
	}
}

func TestHandleArchiveKeyRotate_CommitWithoutBegin(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	seedActiveArchiveKey(t, deps)

	resp := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{})
	if resp.Success {
		t.Fatal("commit without begin must fail")
	}
	if resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Errorf("expected error_code=not_found, got %q", resp.ErrorCode)
	}
}

func TestHandleArchiveKeyRotate_BeginWithoutActiveKey(t *testing.T) {
	deps, _, _ := newTestDeps(t) // no archive key stored

	resp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if resp.Success {
		t.Fatal("begin without an active key must fail (first-time enable is generate)")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Errorf("expected error_code=validation, got %q", resp.ErrorCode)
	}
}

func TestHandleArchiveKeyRotate_RepeatedBeginOverwritesStaging(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveArchiveKey(t, deps)

	first := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !first.Success {
		t.Fatalf("first begin failed: %s", first.Error)
	}
	firstData, _ := first.Data.(proto.ArchiveKeyRotateBeginResponseData)

	second := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !second.Success {
		t.Fatalf("second begin failed: %s", second.Error)
	}
	secondData, _ := second.Data.(proto.ArchiveKeyRotateBeginResponseData)
	if secondData.Fingerprint == firstData.Fingerprint {
		t.Fatal("repeated begin must overwrite staging with a new keypair")
	}

	// Commit promotes the LATEST staged key.
	commit := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{})
	if !commit.Success {
		t.Fatalf("commit failed: %s", commit.Error)
	}
	if pub, err := keychain.GetArchivePublicKey(store); err != nil || pub != secondData.PublicKey {
		t.Fatalf("active key must be the second staged key: %v", err)
	}
}

// The staging design's core invariant: between begin and commit the composite
// re-wrap action still unwraps with the OLD active key, so every existing
// grant can be re-wrapped to the staged public key before the swap.
func TestHandleArchiveKeyRotate_RewrapBeforeCommitUsesOldKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	active := seedActiveArchiveKey(t, deps)

	// A grant wrapped to the CURRENT (old) active public key.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(0x5A + i)
	}
	oldPub, err := crypto.ParsePublicKey(active.PublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey (active): %v", err)
	}
	wrappedToOld, err := crypto.EncryptData(oldPub, dek)
	if err != nil {
		t.Fatalf("EncryptData (active): %v", err)
	}

	beginResp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{})
	if !beginResp.Success {
		t.Fatalf("rotate begin failed: %s", beginResp.Error)
	}
	beginData, _ := beginResp.Data.(proto.ArchiveKeyRotateBeginResponseData)

	// Re-wrap the old-key grant to the STAGED public key — must succeed
	// because the active slot still holds the old private key.
	rewrapResp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrappedToOld),
		RecipientPublicKey:   beginData.PublicKey,
	})
	if !rewrapResp.Success {
		t.Fatalf("re-wrap to staged key before commit failed: %s", rewrapResp.Error)
	}
	rewrapData, _ := rewrapResp.Data.(proto.ArchiveUnwrapAndRewrapResponseData)

	// Commit, then the re-wrapped grant must decrypt with the NEW active key.
	if resp := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{}); !resp.Success {
		t.Fatalf("commit failed: %s", resp.Error)
	}
	newPriv, err := keychain.GetArchivePrivateKey(store)
	if err != nil {
		t.Fatalf("GetArchivePrivateKey (new active): %v", err)
	}
	parsedNewPriv, err := crypto.ParsePrivateKey(newPriv)
	if err != nil {
		t.Fatalf("ParsePrivateKey (new active): %v", err)
	}
	rewrappedRaw, err := base64.StdEncoding.DecodeString(rewrapData.EncryptedForOtherB64)
	if err != nil {
		t.Fatalf("decode re-wrapped grant: %v", err)
	}
	decrypted, err := crypto.DecryptData(parsedNewPriv, rewrappedRaw)
	if err != nil {
		t.Fatalf("re-wrapped grant must decrypt with the new active key: %v", err)
	}
	if string(decrypted) != string(dek) {
		t.Fatal("round-trip mismatch: decrypted DEK differs from original")
	}
}
