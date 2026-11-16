// archive_reconfigure_isolation_test.go — no other action reads the
// reconfiguration private key (lv90 K4).
//
// The key a legacy quorum reconfiguration stages must not open anything
// before the server commits the new configuration: no owner-solo window. Only
// the reconfiguration split (K2) will read it. Each test stages a
// reconfiguration for the fixture's org, runs one handler through its
// success path, and checks that the reconfiguration private key was never
// read, written or deleted.

package handlers

import (
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const reconfigIsolationOp = "ffffffff-ffff-4fff-8fff-ffffffffffff"

// reconfigPrivateProbe counts every access to any org's reconfiguration
// private key.
type reconfigPrivateProbe struct {
	keychain.SecretStore
	touches int
}

func (p *reconfigPrivateProbe) note(account string) {
	if strings.HasPrefix(account, config.OrgArchivePrivateKeyReconfigurationPrefix) {
		p.touches++
	}
}

func (p *reconfigPrivateProbe) Get(service, account string) (string, error) {
	p.note(account)
	return p.SecretStore.Get(service, account)
}

func (p *reconfigPrivateProbe) Set(service, account, value string) error {
	p.note(account)
	return p.SecretStore.Set(service, account, value)
}

func (p *reconfigPrivateProbe) Delete(service, account string) error {
	p.note(account)
	return p.SecretStore.Delete(service, account)
}

// stageForIsolation stages a reconfiguration for orgID, then routes deps
// through a probe. It returns the probe and the staged public key.
func stageForIsolation(t *testing.T, deps *Deps, orgID string) (*reconfigPrivateProbe, string) {
	t.Helper()
	resp := stageReconfiguration(*deps, orgID, reconfigIsolationOp)
	if !resp.Success {
		t.Fatalf("stage: %+v", resp)
	}
	probe := &reconfigPrivateProbe{SecretStore: deps.Store}
	deps.Store = probe
	return probe, resp.Data.(proto.ArchiveReconfigureStageResponseData).PublicKey
}

func requireUntouched(t *testing.T, probe *reconfigPrivateProbe, action string) {
	t.Helper()
	if probe.touches != 0 {
		t.Fatalf("%s touched the reconfiguration private key %d times", action, probe.touches)
	}
}

// signedArchiveRegrant builds a signed archive_unwrap_and_rewrap of a grant
// wrapped to sourcePublic, for operation archive_member_regrant or
// archive_rotation (the latter to a staged rotation key).
func signedArchiveRegrant(t *testing.T, f *auditFixture, operation, sourcePublic string) proto.ArchiveUnwrapAndRewrapRequest {
	t.Helper()
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	device := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, device); err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveUnwrapAndRewrapRequest{OrgID: f.v.OrgID, OwnerAccountID: f.v.AccountID, RecipientPublicKey: f.pubPEM, GrantContext: legacyContext(f.v), WrappedForArchiveB64: f.wrapToMe(t, sourcePublic, legacyContext(f.v))}
	if operation == "archive_rotation" {
		req = rotationRecipient(t, req, archivePinMember)
		if err := keychain.OrgArchiveStagingSlot(f.v.OrgID).SavePublic(f.store, f.pubPEM); err != nil {
			t.Fatal(err)
		}
	} else {
		req.RecipientAccountID = archivePinMember
	}
	prepared := HandleGroupRewrapPrepare(f.deps, proto.GroupRewrapPrepareRequest{Operation: operation, SourceKind: "stored_archive", TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Archive: &req})
	if !prepared.Success {
		t.Fatalf("%s preparation refused: %s", operation, prepared.ErrorCode)
	}
	p := prepared.Data.(proto.GroupRewrapPrepareResponseData)
	decision := proto.GroupRewrapDecision{Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: device, TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Operation: p.Operation, OrgID: p.OrgID, GroupID: p.GroupID, DEKVersion: p.DEKVersion, SourceKind: p.SourceKind, SourceGrantDigest: p.SourceGrantDigest, SourcePolicy: p.SourcePolicy, OutputPolicy: p.OutputPolicy, RequestDigest: p.RequestDigest, RecipientsDigest: p.RecipientsDigest, IssuedAt: f.clock.now().Unix(), ExpiresAt: f.clock.now().Unix() + 10, ServerKeyVersion: 1}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	req.Decision = &decision
	return req
}

// archive_unwrap_and_rewrap opens with the active org archive key and never
// with the staged reconfiguration key.
func TestReconfigurationKeyIsolation_UnwrapUsesOnlyTheActiveKey(t *testing.T) {
	f := newAuditFixture(t)
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(f.store, archive.PrivateKey); err != nil {
		t.Fatal(err)
	}
	req := signedArchiveRegrant(t, f, "archive_member_regrant", archive.PublicKey)
	probe, _ := stageForIsolation(t, &f.deps, f.v.OrgID)
	if resp := HandleArchiveUnwrapAndRewrap(f.deps, req); !resp.Success {
		t.Fatalf("regrant: %+v", resp)
	}
	requireUntouched(t, probe, "archive_unwrap_and_rewrap")
}

// A grant wrapped to the staged reconfiguration key does not open through
// archive_unwrap_and_rewrap: before finalization the new key opens nothing.
func TestReconfigurationKeyIsolation_UnwrapRefusesAGrantToTheStagedKey(t *testing.T) {
	f := newAuditFixture(t)
	resp := stageReconfiguration(f.deps, f.v.OrgID, reconfigIsolationOp)
	if !resp.Success {
		t.Fatalf("stage: %+v", resp)
	}
	staged := resp.Data.(proto.ArchiveReconfigureStageResponseData).PublicKey
	req := signedArchiveRegrant(t, f, "archive_member_regrant", staged)
	probe := &reconfigPrivateProbe{SecretStore: f.deps.Store}
	f.deps.Store = probe
	if out := HandleArchiveUnwrapAndRewrap(f.deps, req); out.Success || out.Data != nil {
		t.Fatalf("a grant to the staged reconfiguration key opened: %+v", out)
	}
	requireUntouched(t, probe, "archive_unwrap_and_rewrap")
}

// The rotation rewrap (to_staged_archive_key) and begin, commit and abort.
func TestReconfigurationKeyIsolation_RotationActions(t *testing.T) {
	t.Run("rotation rewrap", func(t *testing.T) {
		f := newAuditFixture(t)
		archive, err := crypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := keychain.SaveArchivePrivateKey(f.store, archive.PrivateKey); err != nil {
			t.Fatal(err)
		}
		req := signedArchiveRegrant(t, f, "archive_rotation", archive.PublicKey)
		probe, _ := stageForIsolation(t, &f.deps, f.v.OrgID)
		if resp := HandleArchiveUnwrapAndRewrap(f.deps, req); !resp.Success {
			t.Fatalf("rotation rewrap: %+v", resp)
		}
		requireUntouched(t, probe, "archive rotation rewrap")
	})
	t.Run("begin commit abort", func(t *testing.T) {
		deps, _, _ := newTestDeps(t)
		generateFor(t, deps, testOrgA)
		probe, _ := stageForIsolation(t, &deps, testOrgA)
		if resp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{OrgID: testOrgA}); !resp.Success {
			t.Fatalf("begin: %+v", resp)
		}
		if resp := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: testOrgA}); !resp.Success {
			t.Fatalf("commit: %+v", resp)
		}
		if resp := HandleArchiveKeyRotateBegin(deps, proto.ArchiveKeyRotateBeginRequest{OrgID: testOrgA}); !resp.Success {
			t.Fatalf("second begin: %+v", resp)
		}
		if resp := HandleArchiveKeyRotateAbort(deps, proto.ArchiveKeyRotateAbortRequest{OrgID: testOrgA}); !resp.Success {
			t.Fatalf("abort: %+v", resp)
		}
		requireUntouched(t, probe, "archive rotation begin, commit and abort")
	})
}

// archive_share_rewrap opens a share with the account archive key only.
func TestReconfigurationKeyIsolation_ShareRewrap(t *testing.T) {
	f, req, _ := authorizedArchiveShareFixture(t)
	probe, _ := stageForIsolation(t, &f.deps, f.v.OrgID)
	if resp := HandleArchiveShareRewrap(f.deps, req); !resp.Success {
		t.Fatalf("share rewrap: %+v", resp)
	}
	requireUntouched(t, probe, "archive_share_rewrap")
}

// archive_quorum_combine_and_rewrap reconstructs from shares under the
// session key and never consults the staged reconfiguration key.
func TestReconfigurationKeyIsolation_Combine(t *testing.T) {
	f, req := authorizedCombineFixture(t)
	probe, _ := stageForIsolation(t, &f.deps, f.v.OrgID)
	resp := HandleArchiveQuorumCombineAndRewrap(f.deps, req)
	if !resp.Success {
		t.Fatalf("combine: %+v", resp)
	}
	requireUntouched(t, probe, "archive_quorum_combine_and_rewrap")
}

// Status, generate (refused while the reconfiguration is staged), session
// begin, combine and end.
func TestReconfigurationKeyIsolation_StatusGenerateAndSessions(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	probe, _ := stageForIsolation(t, &deps, testOrgA)
	_ = HandleArchiveKeyStatus(deps, proto.ArchiveKeyStatusRequest{OrgID: testOrgA})
	_ = HandleArchiveKeyGenerate(deps, proto.ArchiveKeyGenerateRequest{OrgID: testOrgA})
	pub := beginSessionFor(t, deps, testOrgA)
	req, _ := sessionCombineRequest(t, testOrgA, pub, sessionTestDEK())
	if resp := archiveQuorumCombineAndRewrap(deps, testOrgA, req); !resp.Success {
		t.Fatalf("combine: %+v", resp)
	}
	_ = HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA})
	requireUntouched(t, probe, "archive status, generate and session actions")
}
