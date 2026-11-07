package localrpc

import (
	"encoding/json"
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
