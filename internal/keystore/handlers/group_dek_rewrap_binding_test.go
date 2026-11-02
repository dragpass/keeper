// group_dek_rewrap_binding_test.go — a wrap that names no account may only
// target this Keeper's own account key (protocol.md "Group DEK rewrap
// targets"). Any other key without an account would hand a Native Messaging
// caller the Group DEK under a key it holds.

package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// wrapForStoredKey wraps a fixed 32-byte Group DEK to the stored public key.
func wrapForStoredKey(t *testing.T, myPubPEM string) string {
	t.Helper()
	pub, err := crypto.ParsePublicKey(myPubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	wrapped, err := crypto.EncryptData(pub, dek)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

func TestDEKRewrapForMember_NoAccountRefusesForeignKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)
	foreign, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	resp := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: wrapForStoredKey(t, myPubPEM),
		OtherPublicKey:  foreign.PublicKey,
	})
	if resp.Success {
		t.Fatal("a wrap with no account id to a foreign key must be refused")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error code = %q, want %q", resp.ErrorCode, errs.ErrCodeValidation)
	}
	if resp.Data != nil {
		t.Fatalf("a refused wrap must carry no data, got %#v", resp.Data)
	}
}

// The account key rotation rewraps every grant to the staged key before the
// server accepts it (App route /v1/account-key/rotate/rewrap-group-dek). That
// key is this Keeper's own too, read from its keychain.
func TestDEKRewrapForMember_NoAccountAcceptsStagedRotationKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)
	staged, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if err := keychain.SavePendingPublicKey(store, staged.PublicKey); err != nil {
		t.Fatalf("SavePendingPublicKey: %v", err)
	}

	resp := HandleDEKRewrapForMember(deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: wrapForStoredKey(t, myPubPEM),
		OtherPublicKey:  staged.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("a wrap to the staged rotation key was refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
}

// A new Group DEK is wrapped only to this Keeper's own key; the App route
// already binds it, and Native Messaging must not be able to pick another.
func TestGroupDEKGenerateAndOpen_RefusesForeignKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setupHandlerKeyPair(t, store)
	foreign, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	resp := HandleGroupDEKGenerateAndOpen(deps, proto.GroupDEKGenerateAndOpenRequest{
		MyPublicKey: foreign.PublicKey,
	})
	if resp.Success {
		t.Fatal("a new Group DEK was wrapped to a foreign key")
	}
	if resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("error code = %q, want %q", resp.ErrorCode, errs.ErrCodeValidation)
	}
	if deps.GroupSessions.CloseAll() != 0 {
		t.Fatal("a refused generate opened a handle")
	}
}

// dek_unwrap_and_rewrap_for_many: a recipient without an account id is this
// Keeper's own key, or the one recipient marked as the org archive key.
// Anything else is refused before the Group DEK is unwrapped.
func TestDEKUnwrapAndRewrapForMany_AccountlessRecipientMustBeOwnKeyOrArchive(t *testing.T) {
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)
	foreign, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrapForStoredKey(t, myPubPEM)
	call := func(recipients ...proto.DEKRewrapRecipient) proto.BaseResponse {
		return HandleDEKUnwrapAndRewrapForMany(deps, proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64: wrapped, Recipients: recipients,
		})
	}

	if resp := call(proto.DEKRewrapRecipient{PublicKey: foreign.PublicKey}); resp.Success ||
		resp.ErrorCode != string(errs.ErrCodeValidation) || resp.Data != nil {
		t.Fatalf("an unmarked foreign key without an account was wrapped: %+v", resp)
	}
	if resp := call(
		proto.DEKRewrapRecipient{PublicKey: archive.PublicKey, OrgArchive: true},
		proto.DEKRewrapRecipient{PublicKey: foreign.PublicKey, OrgArchive: true},
	); resp.Success {
		t.Fatal("two org archive recipients were accepted")
	}
	if resp := call(
		proto.DEKRewrapRecipient{PublicKey: myPubPEM},
		proto.DEKRewrapRecipient{PublicKey: archive.PublicKey, OrgArchive: true},
	); !resp.Success {
		t.Fatalf("own key and one org archive recipient were refused: %+v", resp)
	}
}
