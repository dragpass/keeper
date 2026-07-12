// account_archive_key_test.go — per-account Archive / Recovery receiving
// keypair tests: idempotent generate, status, slot separation from the org
// archive keypair, and the archive_unwrap_and_rewrap account-slot fallback
// (handoff-received grants).

package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleAccountArchiveKeyGenerate_IdempotentAndSeparateSlot(t *testing.T) {
	deps, _, store := newTestDeps(t)

	// Pre-existing ORG archive key must not satisfy the account generate.
	orgKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, orgKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, orgKP.PublicKey)

	first := HandleAccountArchiveKeyGenerate(deps, proto.AccountArchiveKeyGenerateRequest{})
	if !first.Success {
		t.Fatalf("generate failed: %s", first.Error)
	}
	firstData := first.Data.(proto.AccountArchiveKeyGenerateResponseData)
	if firstData.PublicKey == orgKP.PublicKey {
		t.Fatal("account archive key must not reuse the org archive key")
	}

	// Second call is idempotent — same meta, no regeneration.
	second := HandleAccountArchiveKeyGenerate(deps, proto.AccountArchiveKeyGenerateRequest{})
	if !second.Success {
		t.Fatalf("second generate failed: %s", second.Error)
	}
	secondData := second.Data.(proto.AccountArchiveKeyGenerateResponseData)
	if secondData.PublicKey != firstData.PublicKey || secondData.Fingerprint != firstData.Fingerprint {
		t.Fatal("account archive generate must be idempotent")
	}

	// Org slot untouched.
	if pub, _ := keychain.GetArchivePublicKey(store); pub != orgKP.PublicKey {
		t.Fatal("org archive public key must be untouched by account generate")
	}
}

func TestHandleAccountArchiveKeyStatus(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	before := HandleAccountArchiveKeyStatus(deps, proto.AccountArchiveKeyStatusRequest{})
	if !before.Success || before.Data.(proto.AccountArchiveKeyStatusResponseData).HasActive {
		t.Fatal("status before generate should be has_active=false")
	}

	gen := HandleAccountArchiveKeyGenerate(deps, proto.AccountArchiveKeyGenerateRequest{})
	genData := gen.Data.(proto.AccountArchiveKeyGenerateResponseData)

	after := HandleAccountArchiveKeyStatus(deps, proto.AccountArchiveKeyStatusRequest{})
	afterData := after.Data.(proto.AccountArchiveKeyStatusResponseData)
	if !afterData.HasActive || afterData.PublicKey != genData.PublicKey || afterData.Fingerprint != genData.Fingerprint {
		t.Fatal("status after generate should return the generated key meta")
	}
}

// A grant wrapped to the ACCOUNT archive key (the ownership-handoff shape —
// grants are re-wrapped to the new owner's account directory key) must still
// unwrap via archive_unwrap_and_rewrap even though the ORG slot holds an
// unrelated key.
func TestHandleArchiveUnwrapAndRewrap_AccountSlotFallback(t *testing.T) {
	deps, _, store := newTestDeps(t)

	// Org slot: unrelated key that cannot decrypt the grant.
	orgKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, orgKP.PrivateKey)

	// Account slot: the key the grant is actually wrapped to.
	accountKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveAccountArchivePrivateKey(store, accountKP.PrivateKey)

	groupDEK := make([]byte, 32)
	for i := range groupDEK {
		groupDEK[i] = byte(0x30 + i)
	}
	accountPub, _ := crypto.ParsePublicKey(accountKP.PublicKey)
	wrapped, _ := crypto.EncryptData(accountPub, groupDEK)

	memberKP, _ := crypto.GenerateRSAKeyPair()
	resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrapped),
		RecipientPublicKey:   memberKP.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("expected account-slot fallback to succeed, got: %s", resp.Error)
	}

	data := resp.Data.(proto.ArchiveUnwrapAndRewrapResponseData)
	memberPriv, _ := crypto.ParsePrivateKey(memberKP.PrivateKey)
	enc, _ := base64.StdEncoding.DecodeString(data.EncryptedForOtherB64)
	dec, err := crypto.DecryptData(memberPriv, enc)
	if err != nil {
		t.Fatalf("member decrypt: %v", err)
	}
	for i := range groupDEK {
		if dec[i] != groupDEK[i] {
			t.Fatalf("fallback rewrap corrupted DEK at byte %d", i)
		}
	}
}

// With neither slot able to decrypt (org key present but wrong, account slot
// empty) the composite fails with crypto_failure; with both slots empty it
// stays not_found.
func TestHandleArchiveUnwrapAndRewrap_FallbackErrorCodes(t *testing.T) {
	t.Run("org wrong, account empty -> crypto_failure", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		orgKP, _ := crypto.GenerateRSAKeyPair()
		_ = keychain.SaveArchivePrivateKey(store, orgKP.PrivateKey)

		otherKP, _ := crypto.GenerateRSAKeyPair()
		otherPub, _ := crypto.ParsePublicKey(otherKP.PublicKey)
		wrapped, _ := crypto.EncryptData(otherPub, make([]byte, 32))

		memberKP, _ := crypto.GenerateRSAKeyPair()
		resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
			WrappedForArchiveB64: base64.StdEncoding.EncodeToString(wrapped),
			RecipientPublicKey:   memberKP.PublicKey,
		})
		if resp.Success {
			t.Fatal("expected failure")
		}
		if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
			t.Errorf("expected crypto_failure, got %q", resp.ErrorCode)
		}
	})

	t.Run("both slots empty -> not_found", func(t *testing.T) {
		deps, _, _ := newTestDeps(t)
		memberKP, _ := crypto.GenerateRSAKeyPair()
		resp := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
			WrappedForArchiveB64: base64.StdEncoding.EncodeToString([]byte("x")),
			RecipientPublicKey:   memberKP.PublicKey,
		})
		if resp.Success {
			t.Fatal("expected failure")
		}
		if resp.ErrorCode != string(errs.ErrCodeNotFound) {
			t.Errorf("expected not_found, got %q", resp.ErrorCode)
		}
	})
}
