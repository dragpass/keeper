package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestPendingKeyRewrapRefusesCallerChosenTarget(t *testing.T) {
	f := newAuditFixture(t)
	pending, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPublicKey(f.store, pending.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPrivateKey(f.store, pending.PrivateKey); err != nil {
		t.Fatal(err)
	}
	request := proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		OtherPublicKey:  f.pubPEM,
	}
	if response := HandleDEKRewrapToPendingKey(f.deps, request); response.Success {
		t.Fatal("active key accepted as rotation's pending target")
	}
	request.OtherPublicKey = pending.PublicKey
	if response := HandleDEKRewrapToPendingKey(f.deps, request); !response.Success {
		t.Fatalf("Keeper-held pending key refused: %s", response.ErrorCode)
	}
}
