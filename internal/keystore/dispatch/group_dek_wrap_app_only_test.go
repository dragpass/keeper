//go:build !keeper_e2e

package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A Group DEK wrapped to a caller's key opens bound tokens offline, so the
// three wrap actions run only for the paired App (protocol.md "Group DEK
// rewrap targets"). A release build refuses them to every Native Messaging
// frame.
func TestGroupDEKWrapActionsAreAppOnlyInRelease(t *testing.T) {
	for _, name := range []string{
		proto.ActionGroupRewrapPrepare,
		proto.ActionGroupDEKGenerateAndOpen,
		proto.ActionDEKRewrapForMember,
		proto.ActionDEKUnwrapAndRewrapForMany,
	} {
		entry, ok := actionRegistry[name]
		if !ok || !entry.appOnly || entry.mcp || entry.plaintext {
			t.Fatalf("%s must be App-only without plaintext output", name)
		}
		if !AppOnly(name) {
			t.Fatalf("%s must be refused to Native Messaging in a release build", name)
		}
	}
}

func TestMemberRewrapDispatchRefusesUnsignedExecution(t *testing.T) {
	key, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: "YQ==", OtherPublicKey: key.PublicKey,
		OwnerAccountID: "11111111-1111-4111-8111-111111111111",
		OtherAccountID: "22222222-2222-4222-8222-222222222222",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := actionRegistry[proto.ActionDEKRewrapForMember].handle(handlers.Deps{}, payload)
	if response.Success || response.ErrorCode != "not_found" || response.Data != nil {
		t.Fatalf("unsigned external rewrap was not refused: success=%t code=%s", response.Success, response.ErrorCode)
	}
}

func TestPendingKeyRewrapDispatchRequiresKeeperState(t *testing.T) {
	key, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: "YQ==", OtherPublicKey: key.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := actionRegistry[proto.ActionDEKRewrapToPendingKey].handle(handlers.Deps{}, payload)
	if response.Success || response.ErrorCode != "not_found" || response.Data != nil {
		t.Fatalf("pending-key action used a caller key without Keeper state: success=%t code=%s", response.Success, response.ErrorCode)
	}
}
