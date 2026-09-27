package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleKeyTransparencyStatusShowsUnconfiguredAndUnanchored(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	response := HandleKeyTransparencyStatus(deps, proto.KeyTransparencyStatusRequest{})
	if !response.Success {
		t.Fatalf("status failed: %s", response.Error)
	}
	status, ok := response.Data.(proto.KeyTransparencyStatusResponse)
	if !ok || status.Configured || status.Anchored {
		t.Fatalf("status = %#v, want unconfigured and unanchored", response.Data)
	}
}

func TestRotationTransparencyFailsClosedWithoutTrust(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	deps.RequireKeyTransparency = true
	statement := proto.KeyRotationStatement{AccountID: trustPeerAccount}
	err := verifyRotationTransparency(deps, []proto.KeyRotationStatement{statement})
	if err != keytransparency.ErrTrustUnavailable {
		t.Fatalf("verifyRotationTransparency error = %v, want trust unavailable", err)
	}
}
