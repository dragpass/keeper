package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
	"reflect"
	"testing"
)

func rotationRecipient(t *testing.T, req proto.ArchiveUnwrapAndRewrapRequest, _ string) proto.ArchiveUnwrapAndRewrapRequest {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["to_staged_archive_key"], err = json.Marshal(true)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestArchiveRotationPreparedSignedRoundTrip(t *testing.T) {
	runArchiveRotationPrepared(t, false)
}

func TestArchiveRotationRejectsReplacedStage(t *testing.T) {
	runArchiveRotationPrepared(t, true)
}

func runArchiveRotationPrepared(t *testing.T, replaceStage bool) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	device := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, device); err != nil {
		t.Fatal(err)
	}
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(f.store, archive.PrivateKey); err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveUnwrapAndRewrapRequest{OrgID: f.v.OrgID, OwnerAccountID: f.v.AccountID, RecipientPublicKey: f.pubPEM, GrantContext: legacyContext(f.v), WrappedForArchiveB64: f.wrapToMe(t, archive.PublicKey, legacyContext(f.v))}
	req = rotationRecipient(t, req, archivePinMember)
	if err := keychain.OrgArchiveStagingSlot(f.v.OrgID).SavePublic(f.store, f.pubPEM); err != nil {
		t.Fatal(err)
	}
	prepared := HandleGroupRewrapPrepare(f.deps, proto.GroupRewrapPrepareRequest{Operation: "archive_rotation", SourceKind: "stored_archive", TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Archive: &req})
	if !prepared.Success {
		t.Fatalf("archive preparation refused: %s", prepared.ErrorCode)
	}
	p := prepared.Data.(proto.GroupRewrapPrepareResponseData)
	decision := proto.GroupRewrapDecision{Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: device, TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Operation: p.Operation, OrgID: p.OrgID, GroupID: p.GroupID, DEKVersion: p.DEKVersion, SourceKind: p.SourceKind, SourceGrantDigest: p.SourceGrantDigest, SourcePolicy: p.SourcePolicy, OutputPolicy: p.OutputPolicy, RequestDigest: p.RequestDigest, RecipientsDigest: p.RecipientsDigest, IssuedAt: f.clock.now().Unix(), ExpiresAt: f.clock.now().Unix() + 10, ServerKeyVersion: 1}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	req.Decision = &decision
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	for _, kind := range []string{"recipient", "source", "signature", "operation"} {
		changed := req
		altered := decision
		changed.Decision = &altered
		switch kind {
		case "recipient":
			changed.RecipientAccountID = "88888888-8888-4888-8888-888888888888"
		case "source":
			changed.WrappedForArchiveB64 = "AA=="
		case "signature":
			altered.Signature = "AA=="
		case "operation":
			altered.Operation = "archive_member_regrant"
			altered.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(altered))
		}
		rejected := HandleArchiveUnwrapAndRewrap(f.deps, changed)
		if rejected.Success || rejected.Data != nil {
			t.Fatalf("changed %s returned a grant", kind)
		}
		if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
			t.Fatalf("changed %s mutated private state", kind)
		}
	}
	if replaceStage {
		if err := keychain.OrgArchiveStagingSlot(f.v.OrgID).SavePublic(f.store, archive.PublicKey); err != nil {
			t.Fatal(err)
		}
		snapshot := f.store.(*testdouble.MemorySecretStore).Snapshot()
		refused := HandleArchiveUnwrapAndRewrap(f.deps, req)
		if refused.Success || refused.Data != nil {
			t.Fatal("replaced stage returned wrapped output")
		}
		if !reflect.DeepEqual(snapshot, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
			t.Fatal("replaced stage changed key or pin state")
		}
		return
	}
	response := HandleArchiveUnwrapAndRewrap(f.deps, req)
	if !response.Success {
		t.Fatalf("authorized archive regrant refused: %s", response.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("archive handoff mutated peer pins")
	}
	out := response.Data.(proto.ArchiveUnwrapAndRewrapResponseData)
	encrypted, err := base64.StdEncoding.DecodeString(out.EncryptedForOtherB64)
	if err != nil {
		t.Fatal(err)
	}
	privBuf, err := GetPrivateKeySecure(f.store)
	if err != nil {
		t.Fatal(err)
	}
	defer privBuf.Destroy()
	priv, err := crypto.ParsePrivateKey(string(privBuf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := unwrapGrant(priv, encrypted, legacyContext(f.v))
	if err != nil || !bytes.Equal(actual, mustHex(t, f.v.GroupDEKHex)) {
		t.Fatal("authorized archive result changed the DEK")
	}
	if replay := HandleArchiveUnwrapAndRewrap(f.deps, req); replay.Success || replay.Data != nil {
		t.Fatal("reused archive regrant returned output")
	}
}
