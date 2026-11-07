package localrpc

import (
	"encoding/json"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"testing"
)

func TestArchiveHandoffRouteBindsNamedArchiveRecipient(t *testing.T) {
	server, _ := newChatTestServer(t)
	key := routeKeypair(t)
	body, err := json.Marshal(map[string]any{"org_id": routeOwner, "owner_account_id": routeOwner, "archive_recipient_account_id": routePeer, "account_archive_public_key": key.PublicKey, "wrapped_for_archive_b64": "AA=="})
	if err != nil {
		t.Fatal(err)
	}
	var request appArchiveRewrap
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	bound, err := bindArchiveRewrap(server, &request)
	if err != nil {
		t.Fatalf("named handoff binding refused: %v", err)
	}
	result := bound.(proto.ArchiveUnwrapAndRewrapRequest)
	if result.ArchiveRecipientAccountID != routePeer || result.OwnerAccountID != routeOwner || result.RecipientAccountID != "" || result.RecipientPublicKey != key.PublicKey {
		t.Fatal("archive recipient binding changed")
	}
}

func TestArchiveRotationRouteBindsNamedOwnerAndStage(t *testing.T) {
	server, _ := newChatTestServer(t)
	key := routeKeypair(t)
	if err := keychain.OrgArchiveStagingSlot(routeOwner).SavePublic(server.app.Store, key.PublicKey); err != nil {
		t.Fatal(err)
	}
	bound, err := bindArchiveRewrap(server, &appArchiveRewrap{OrgID: routeOwner, OwnerAccountID: routeOwner, ToStagedArchiveKey: true, WrappedForArchiveB64: "AA=="})
	if err != nil {
		t.Fatalf("named rotation binding refused: %v", err)
	}
	result := bound.(proto.ArchiveUnwrapAndRewrapRequest)
	if !result.ToStagedArchiveKey || result.OwnerAccountID != routeOwner || result.RecipientPublicKey != key.PublicKey {
		t.Fatal("rotation did not bind current stage and owner")
	}
}
