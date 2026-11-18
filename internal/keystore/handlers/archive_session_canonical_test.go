// archive_session_canonical_test.go — session fingerprints are lowercase
// hex, as begin returns them; anything else is refused at validation.

package handlers

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// An uppercase (or mixed-case) fingerprint names no key Keeper stores, so
// every session action refuses it with validation_error and changes
// nothing, rather than reading it as a fingerprint that never matches.
func TestArchiveSessionFingerprint_NonCanonicalIsRefusedAtValidation(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	before := store.Snapshot()
	for _, fp := range []string{strings.ToUpper(a.Fingerprint), "A" + a.Fingerprint[1:]} {
		for name, resp := range map[string]proto.BaseResponse{
			"set_expiry": setExpiry(deps, testOrgA, fp, clock.Now().Add(-time.Minute)),
			"end":        HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: fp}),
			"discard":    discardSession(deps, testOrgA, fp),
			"status":     HandleArchiveSessionStatus(deps, proto.ArchiveSessionStatusRequest{OrgID: testOrgA, Fingerprint: fp}),
		} {
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
				t.Fatalf("%s with a non-canonical fingerprint: success=%v code=%q", name, resp.Success, resp.ErrorCode)
			}
		}
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a refused request changed the keychain")
	}
}
