package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

type capabilityUserPresence struct {
	userpresence.Unavailable
}

func (capabilityUserPresence) Capabilities() userpresence.Capabilities {
	return userpresence.Capabilities{
		Available:       true,
		PromptSecret:    true,
		Confirm:         true,
		ShowRecoveryKey: true,
		Backend:         "test",
	}
}

func TestHandleUserPresenceCapabilities(t *testing.T) {
	resp := HandleUserPresenceCapabilities(
		Deps{UserPresence: capabilityUserPresence{}},
		proto.UserPresenceCapabilitiesRequest{},
	)
	if !resp.Success {
		t.Fatalf("expected success, got %v", resp.Error)
	}
	data, ok := resp.Data.(proto.UserPresenceCapabilitiesResponseData)
	if !ok {
		t.Fatalf("unexpected response type %T", resp.Data)
	}
	if !data.Available || !data.PromptSecret || !data.Confirm || !data.ShowRecoveryKey {
		t.Fatalf("capabilities not propagated: %+v", data)
	}
	if data.Backend != "test" {
		t.Fatalf("backend = %q, want test", data.Backend)
	}
}
