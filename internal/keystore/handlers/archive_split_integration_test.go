package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"testing"
)

func TestArchiveSplitIntegrationPreservesOriginalBeforeConfirmation(t *testing.T) {
	d, _, store := newTestDeps(t)
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePublicKey(store, kp.PublicKey); err != nil {
		t.Fatal(err)
	}
	_, recipients := genAdminKeys(t, 2)
	response := HandleArchiveKeySplit(d, proto.ArchiveKeySplitRequest{OperationID: "44444444-4444-4444-8444-444444444444", ThresholdN: 2, RecipientPublicKeys: recipients})
	if !response.Success {
		t.Fatal("split preparation refused")
	}
	actual, err := keychain.GetArchivePrivateKey(store)
	if err != nil || actual != kp.PrivateKey {
		t.Fatal("original archive key lost before server confirmation and participant proofs")
	}
}
