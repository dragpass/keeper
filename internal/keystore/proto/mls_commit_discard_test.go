// mls_commit_discard_test.go — which server answers may discard a pending
// Commit (lv78). Discarding a Commit the server took or still holds forks this
// device off the group, so an answer that says the server holds the Commit is
// never a discard reason, whatever the allowed list says.

package proto

import (
	"errors"
	"slices"
	"testing"
)

func discardRequest(code string) MLSCommitDiscardRefusedRequest {
	return MLSCommitDiscardRefusedRequest{
		Permit:         stateValidPermit(),
		OrgID:          stateFixtureOrgID,
		ConversationID: stateFixtureConvID,
		ClientCommitID: "44444444-4444-4444-8444-444444444444",
		ExpectedEpoch:  1,
		RefusalCode:    code,
	}
}

func refusedField(t *testing.T, err error) string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want a validation error, got %v", err)
	}
	return ve.Field
}

// The allowed set is exactly the seven definitive refusals.
func TestMLSCommitDiscardRefused_AllowedCodesArePinned(t *testing.T) {
	want := []string{
		"CHAT_ACCESS_DENIED",
		"CHAT_MLS_MEMBER_SET_STALE",
		"CHAT_MLS_REMOVAL_PENDING",
		"CHAT_ROOM_MEMBER_LIMIT",
		"CHAT_ROOM_OWNER_LEAVING",
		"CHAT_ROOM_ROLE_REQUIRED",
		"CHAT_SELF_REMOVE_REFUSED",
	}
	if !slices.Equal(MLSCommitDiscardRefusedDefinitiveCodes, want) {
		t.Fatalf("allowed codes %v, want %v", MLSCommitDiscardRefusedDefinitiveCodes, want)
	}
	for _, code := range want {
		if err := discardRequest(code).Validate(); err != nil {
			t.Fatalf("%s refused: %v", code, err)
		}
	}
}

// An answer that means the server holds, or may hold, the Commit is never a
// discard reason, even if it were added to the allowed set by mistake.
func TestMLSCommitDiscardRefused_NeverForAnAnswerThatKeepsTheCommit(t *testing.T) {
	for _, code := range MLSCommitNeverDiscardCodes {
		if slices.Contains(MLSCommitDiscardRefusedDefinitiveCodes, code) {
			t.Fatalf("%s is both allowed and never-discard", code)
		}
		if field := refusedField(t, discardRequest(code).Validate()); field != "refusal_code" {
			t.Fatalf("%s refused on %q", code, field)
		}
	}
	if !slices.Contains(MLSCommitNeverDiscardCodes, "CHAT_MLS_REMOVAL_IN_PROGRESS") {
		t.Fatal("CHAT_MLS_REMOVAL_IN_PROGRESS is not a never-discard answer")
	}

	saved := MLSCommitDiscardRefusedDefinitiveCodes
	defer func() { MLSCommitDiscardRefusedDefinitiveCodes = saved }()
	MLSCommitDiscardRefusedDefinitiveCodes = append(slices.Clone(saved), MLSCommitNeverDiscardCodes...)
	for _, code := range MLSCommitNeverDiscardCodes {
		if err := discardRequest(code).Validate(); err == nil {
			t.Fatalf("%s accepted as a discard reason once listed as allowed", code)
		}
	}
}
