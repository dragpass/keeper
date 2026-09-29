package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	formatlog "github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

func TestKeyTransparencyMonitorVerifiesAndClassifiesAccountEvents(t *testing.T) {
	accountID := "00000000-0000-4000-8000-000000000001"
	oldKey, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	oldPrivate, err := keepercrypto.ParsePrivateKey(oldKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	newPrivate, err := keepercrypto.ParsePrivateKey(newKey.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	rotation := proto.KeyRotationStatement{
		AccountID: accountID, OldFingerprint: keepercrypto.AccountKeyFingerprint([]byte(oldKey.PublicKey)),
		NewFingerprint: keepercrypto.AccountKeyFingerprint([]byte(newKey.PublicKey)), RotatedAt: 1700000000,
		Reason:       proto.KeyRotationReasonVoluntary,
		OldPublicKey: base64.StdEncoding.EncodeToString([]byte(oldKey.PublicKey)),
		NewPublicKey: base64.StdEncoding.EncodeToString([]byte(newKey.PublicKey)),
	}
	oldSignature, err := keepercrypto.SignData(oldPrivate, rotation.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	newSignature, err := keepercrypto.SignData(newPrivate, rotation.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	rotation.OldSignature = base64.StdEncoding.EncodeToString(oldSignature)
	rotation.NewSignature = base64.StdEncoding.EncodeToString(newSignature)
	statement, err := keytransparency.EncodeAccountKeyRotationStatement(rotation)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, statement)
	store := keychain.NewMemorySecretStore()
	deps, _, _ := newTestDeps(t)
	deps.Store = store
	deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	request := proto.KeyTransparencyMonitorRequest{
		AccountID: accountID,
		Events: []proto.KeyTransparencyMonitorEventRequest{{
			EventID: "00000000-0000-4000-8000-000000000002", SourceType: keytransparency.StatementAccountKeyRotation,
			Evidence: evidence,
		}},
	}
	response := HandleKeyTransparencyMonitor(deps, request)
	if !response.Success {
		t.Fatalf("monitor failed: %s (%s)", response.Error, response.ErrorCode)
	}
	result := response.Data.(proto.KeyTransparencyMonitorResponse)
	if result.Checked != 1 || result.CheckpointSize != 1 || len(result.Events) != 1 || result.Events[0].KnownOnThisDevice {
		t.Fatalf("first scan result = %+v", result)
	}
	pendingID, err := keychain.PendingKeyTransparencyEventID([]byte(newKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.StageKeyTransparencyEvent(store, accountID, pendingID, statement); err != nil {
		t.Fatal(err)
	}
	if err := keychain.PromoteKeyTransparencyEvent(store, pendingID); err != nil {
		t.Fatal(err)
	}
	response = HandleKeyTransparencyMonitor(deps, request)
	if !response.Success || !response.Data.(proto.KeyTransparencyMonitorResponse).Events[0].KnownOnThisDevice {
		t.Fatalf("known event was not recognized: %+v", response)
	}
	request.Events[0].SourceType = keytransparency.StatementMLSLeafBinding
	if refused := HandleKeyTransparencyMonitor(deps, request); refused.Success {
		t.Fatal("accepted a source type that did not match the signed statement")
	}
}

func signedStatementEvidence(t *testing.T, statement []byte) (proto.KeyTransparencyEvidence, *keytransparency.Trust) {
	t.Helper()
	logPrivate, logPublic, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x31}, 4096)), "dragpass.test/log")
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := note.NewSigner(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	logVerifier, err := note.NewVerifier(logPublic)
	if err != nil {
		t.Fatal(err)
	}
	witnessSigners := make([]note.Signer, 2)
	witnessVerifiers := make([]note.Verifier, 2)
	for index := range witnessSigners {
		private, public, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{byte(index + 0x41)}, 4096)), string(rune('a'+index))+".witness")
		if err != nil {
			t.Fatal(err)
		}
		witnessSigners[index], err = formatnote.NewSignerForCosignatureV1(private)
		if err != nil {
			t.Fatal(err)
		}
		witnessVerifiers[index], err = formatnote.NewVerifierForCosignatureV1(public)
		if err != nil {
			t.Fatal(err)
		}
	}
	trust := &keytransparency.Trust{
		Origin: "dragpass.test/log", LogVerifier: logVerifier, WitnessVerifiers: witnessVerifiers,
		Quorum: 2, MaxCheckpointAge: time.Hour, FutureSkew: time.Minute,
	}
	salt := bytes.Repeat([]byte{0x53}, 32)
	commitInput := append([]byte("dragpass.kt.leaf.v1\x00"), salt...)
	commitInput = binary.BigEndian.AppendUint32(commitInput, uint32(len(statement)))
	commitInput = append(commitInput, statement...)
	commitment := sha256.Sum256(commitInput)
	leaf := rfc6962.DefaultHasher.HashLeaf(commitment[:])
	checkpoint := formatlog.Checkpoint{Origin: trust.Origin, Size: 1, Hash: leaf}
	raw, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	verifiers := append([]note.Verifier{logVerifier}, witnessVerifiers...)
	signed, err := note.Open(raw, note.VerifierList(verifiers...))
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range witnessSigners {
		raw, err = note.Sign(signed, signer)
		if err != nil {
			t.Fatal(err)
		}
		signed, err = note.Open(raw, note.VerifierList(verifiers...))
		if err != nil {
			t.Fatal(err)
		}
	}
	return proto.KeyTransparencyEvidence{
		StatementB64: base64.StdEncoding.EncodeToString(statement), SaltB64: base64.StdEncoding.EncodeToString(salt),
		CheckpointB64: base64.StdEncoding.EncodeToString(raw), LeafIndex: 0,
	}, trust
}
