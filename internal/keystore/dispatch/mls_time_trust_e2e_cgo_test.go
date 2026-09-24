//go:build mls && cgo

// N2: what a server that sets times into the past, or serves old material,
// can make a Keeper accept. The only times a server chooses are the ones it
// signs (a permit, a challenge); every time a validity rule reads beyond those
// is signed by an account (a statement, a leaf declaration), and the clock
// they are judged against is this Keeper's. These tests pin each case, and
// the one gap they found is stated rather than hidden.

package dispatch

import (
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A permit the server issued in the past, beyond its window, opens nothing.
func TestMLSTimeTrust_APermitFromThePastIsRefused(t *testing.T) {
	c := newDM(t)
	old := c.alice.permit()
	old.IssuedAt -= 3600
	old.ExpiresAt -= 3600
	req := c.alice.encryptRequest(messageID(1), 1, "hi")
	req.Permit = old
	c.alice.refused(proto.MLSEncrypt, req, proto.ChatStateErrorCodeNotAuthorized)
}

// A KeyPackage whose embedded declaration has expired by this Keeper's clock
// is refused at the Add, whatever the server says about it: it can only
// serve what the account signed, and the expiry is read here.
func TestMLSTimeTrust_AnExpiredKeyPackageIsRefusedAtTheAdd(t *testing.T) {
	r := newRolesRoom(t)
	dave := newKeeper(t, e2eDave)
	kp := dave.keyPackage()
	r.alice.deps.Clock = func() time.Time {
		return time.Now().Add(time.Duration(proto.MLSLeafMaxValiditySeconds+3600) * time.Second)
	}
	defer func() { r.alice.deps.Clock = nil }()
	req := r.alice.buildRequest(1)
	req.Permit = r.alice.permitAt(time.Duration(proto.MLSLeafMaxValiditySeconds+3600) * time.Second)
	req.Add, req.UserInitiated = []proto.MLSMemberKeyPackage{kp}, true
	resp := r.alice.call(proto.MLSCommitBuild, req)
	assertCode(t, resp, proto.ChatMLSErrorCodeLeafUntrusted)
	if !r.alice.deps.Logger.(*logger.MemoryLogger).Contains("leaf declaration has expired") {
		t.Fatalf("refused for another reason than the expiry: %+v", resp)
	}
}

// A KeyPackage of Bob's device from before his account recovery, re-served
// after it: the adder's pin moved to the recovered key, so the old account key
// is a change and the leaf is refused.
func TestMLSTimeTrust_APreRecoveryKeyPackageIsRefusedAfterTheRecovery(t *testing.T) {
	r := newRolesRoom(t)
	stale := r.bob.keyPackage()
	bob2, chain := recoveredKeeper(t, r.bob, e2eDevice2)
	decl := bob2.declare(proto.MLSLeafReasonRotate, time.Now().Unix()+60)
	r.alice.replacing = []proto.ChatStateLeafReplacement{{AccountID: e2eBob, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	// Alice seats the recovered identity (she is the owner) and her pin for
	// Bob moves to the new key.
	built := commitOf(mustSucceed(t, "alice seats bob2",
		r.alice.buildRecoveryReplace(1, bob2.keyPackage(), true, chain)))
	r.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	r.alice.replacing = nil
	// Remove bob2 again, then try the stale pre-recovery KeyPackage.
	req := r.alice.buildRequest(2)
	req.RemoveAccountIDs, req.UserInitiated = []string{e2eBob}, true
	r.alice.accepted(req)
	add := r.alice.buildRequest(3)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{stale}, true
	assertCode(t, r.alice.call(proto.MLSCommitBuild, add), proto.ChatMLSErrorCodeLeafUntrusted)
}

// The gap: a device whose leaf was removed on its account's signed
// revocation can be added again from a KeyPackage it minted before the
// revocation, if a server serves one. The adder's Keeper verified and applied
// the revocation, but keeps no record of it, and the old declaration is still
// the newest this device has seen for the account. Times play no part: the
// KeyPackage and its declaration are within their own lifetimes. Pinned so it
// is not mistaken for a guarantee (reported as a residual risk and a question).
func TestMLSTimeTrust_ARevokedDevicesOldKeyPackageIsStillAcceptedAsStated(t *testing.T) {
	r := newRolesRoom(t)
	stale := r.carol.keyPackage()
	revocation := r.carol.revokeOwnDevice()
	req := r.bob.buildRequest(1)
	req.DeviceRevocations = []proto.MLSDeviceRevocation{revocation}
	req.RevokeDevices = []proto.MLSDeviceRef{{AccountID: e2eCarol, DeviceID: r.carol.device}}
	removed := r.bob.accepted(req)
	if got := r.alice.process(r.nextSeq(), 2, removed.CommitB64); got.Epoch != 2 {
		t.Fatalf("alice applied the revocation at %+v", got)
	}
	add := r.alice.buildRequest(2)
	add.Add, add.UserInitiated = []proto.MLSMemberKeyPackage{stale}, true
	if resp := r.alice.call(proto.MLSCommitBuild, add); !resp.Success {
		t.Fatalf("the stated gap closed (a revoked device's old key package is now refused: %+v); update this test and the design doc", resp)
	}
}

// permitAt is permit issued ahead by skew, for a Keeper whose clock reads that
// much later.
func (k *keeper) permitAt(skew time.Duration) proto.ChatStatePermit {
	p := k.permit()
	p.IssuedAt += int64(skew / time.Second)
	p.ExpiresAt += int64(skew / time.Second)
	return p
}
