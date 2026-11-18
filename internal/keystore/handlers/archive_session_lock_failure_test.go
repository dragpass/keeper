// archive_session_lock_failure_test.go — when the keychain process lock
// cannot be taken, every session action answers storage_failure and writes
// nothing.

package handlers

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestArchiveSession_LockFailureIsStorageFailureAndWritesNothing(t *testing.T) {
	deps, store, clock := newOrgSessionDeps(t)
	a := beginOrgSession(t, deps, testOrgA)
	saveLegacyDeviceSession(t, store)
	clock.Set(clock.Now().Add(time.Hour)) // A has expired: a sweep would delete it
	before := store.Snapshot()
	restore := archiveSessionProcessLock
	t.Cleanup(func() { archiveSessionProcessLock = restore })
	archiveSessionProcessLock = func(keychain.SecretStore, func() error) error {
		return errors.New("injected lock timeout")
	}
	for name, resp := range map[string]proto.BaseResponse{
		"begin":          beginWithID(deps, testOrgA, testBeginID1),
		"set_expiry":     setExpiry(deps, testOrgA, a.Fingerprint, clock.Now()),
		"end":            HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: a.Fingerprint}),
		"discard":        discardSession(deps, testOrgA, a.Fingerprint),
		"status":         HandleArchiveSessionStatus(deps, proto.ArchiveSessionStatusRequest{OrgID: testOrgA}),
		"legacy_discard": HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true}),
	} {
		if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) || resp.Data != nil {
			t.Errorf("%s without the lock: success=%v code=%q data=%v", name, resp.Success, resp.ErrorCode, resp.Data)
		}
	}
	SweepExpiredArchiveSession(deps)
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("an action wrote without the lock")
	}
}
