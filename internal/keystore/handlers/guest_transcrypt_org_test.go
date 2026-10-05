package handlers

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	transcryptOrgA = "11111111-1111-4111-8111-111111111111"
	transcryptOrgB = "22222222-2222-4222-8222-222222222222"
)

func openLabeledSession(t *testing.T, deps Deps, orgID string) (string, []byte) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	handle, _, err := deps.GroupSessions.OpenLabeled(append([]byte(nil), raw...), orgID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { deps.GroupSessions.Close(handle) })
	return handle, raw
}

func transcryptUnder(deps Deps, handle string, groupRaw []byte, t *testing.T, expected string) proto.BaseResponse {
	ivB64, ctB64 := sealOrgToken(t, groupRaw, []byte("ORG_BOUND_SENTINEL"))
	return HandleGroupTranscryptForGuest(deps, proto.GroupTranscryptForGuestRequest{
		GroupHandle:   handle,
		IVB64:         ivB64,
		CiphertextB64: ctB64,
		ExpectedOrgID: expected,
	})
}

func TestGuestTranscryptRunsWhenTheHandleOrgIsTheExpectedOrg(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, raw := openLabeledSession(t, deps, transcryptOrgA)
	resp := transcryptUnder(deps, handle, raw, t, transcryptOrgA)
	if !resp.Success {
		t.Fatalf("same-org transcrypt refused: %s", resp.Error)
	}
	data := resp.Data.(proto.GroupTranscryptForGuestResponseData)
	if string(guestViewerDecrypt(t, data.GuestCiphertext, data.GuestKey, "", "")) != "ORG_BOUND_SENTINEL" {
		t.Fatal("the guest key does not open the share")
	}
}

// A token decrypted under org A's grant is never re-shared under org B's
// policy: the refusal comes before decryption and carries no guest output.
func TestGuestTranscryptRefusesAHandleOpenedForAnotherOrg(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, raw := openLabeledSession(t, deps, transcryptOrgA)
	resp := transcryptUnder(deps, handle, raw, t, transcryptOrgB)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("cross-org transcrypt: success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !strings.Contains(resp.Error, "expected_org_id") || resp.Data != nil {
		t.Fatalf("refusal = %q data=%v", resp.Error, resp.Data)
	}
}

func TestGuestTranscryptWithAnExpectedOrgRefusesAHandleOpenedForNone(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, raw := openSessionForFreshKey(t, deps)
	if resp := transcryptUnder(deps, handle, raw, t, transcryptOrgA); resp.Success {
		t.Fatal("an unlabeled handle transcrypted under an expected org")
	}
}

// Native Messaging clients at the 0.0.57 floor send neither field.
func TestGuestTranscryptWithoutAnExpectedOrgIsUnchanged(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	for _, org := range []string{"", transcryptOrgA} {
		handle, raw := openLabeledSession(t, deps, org)
		if resp := transcryptUnder(deps, handle, raw, t, ""); !resp.Success {
			t.Fatalf("handle org %q without expected_org_id: %s", org, resp.Error)
		}
	}
}

func TestGuestTranscryptOrgFieldsMustBeLowercaseUUIDs(t *testing.T) {
	for _, bad := range []string{"not-a-uuid", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "00000000-0000-0000-0000-000000000000"} {
		transcrypt := proto.GroupTranscryptForGuestRequest{
			GroupHandle:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			IVB64:         "AAAAAAAAAAAAAAAA",
			CiphertextB64: "AAAA",
			ExpectedOrgID: bad,
		}
		if transcrypt.Validate() == nil {
			t.Fatalf("expected_org_id %q accepted", bad)
		}
		open := proto.GroupSessionOpenRequest{EncryptedGroupDEK: "AAAA", OrgID: bad}
		if open.Validate() == nil {
			t.Fatalf("org_id %q accepted", bad)
		}
	}
}
