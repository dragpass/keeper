// registry_test.go — guards for the fragment-assembly registry.

package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func noopHandler(handlers.Deps, json.RawMessage) proto.BaseResponse {
	return proto.BaseResponse{Success: true}
}

// TestBuildRegistry_PanicsOnDuplicateAction proves the cross-file guard: two
// domain fragments claiming the same action string must fail loudly rather than
// silently shadow one another.
func TestBuildRegistry_PanicsOnDuplicateAction(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("buildRegistry did not panic on a duplicate action across fragments")
		}
	}()

	buildRegistry([]actionFragment{
		func() map[string]actionHandlerFunc {
			return map[string]actionHandlerFunc{proto.ActionPing: noopHandler}
		},
		func() map[string]actionHandlerFunc {
			return map[string]actionHandlerFunc{proto.ActionPing: noopHandler}
		},
	})
}

// TestBuildRegistry_MergesDisjointFragments confirms disjoint fragments combine
// into the union without loss.
func TestBuildRegistry_MergesDisjointFragments(t *testing.T) {
	reg := buildRegistry([]actionFragment{
		func() map[string]actionHandlerFunc {
			return map[string]actionHandlerFunc{proto.ActionPing: noopHandler}
		},
		func() map[string]actionHandlerFunc {
			return map[string]actionHandlerFunc{proto.ActionGetPublicKey: noopHandler}
		},
	})
	if len(reg) != 2 {
		t.Fatalf("merged registry size = %d, want 2", len(reg))
	}
}
