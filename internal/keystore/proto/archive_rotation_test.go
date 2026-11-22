package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Fixed vectors cover the server canonical layout, including byte lengths,
// the decimal session timestamp and ciphertext bytes in the grant digest.
func TestArchiveRotationWireVectors(t *testing.T) {
	account, org, op, session, grant, group, device := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004", "00000000-0000-4000-8000-000000000005", "00000000-0000-4000-8000-000000000006", "00000000-0000-4000-8000-000000000007"
	r := ArchiveRotationRequest{OrgID: org, OperationID: op, SessionID: session, ConfigDigest: strings.Repeat("1", 64),
		Shares: []RotationShare{{account, 1, "d2s=", "Y3Q="}, {device, 2, "d2s=", "Y3Q="}},
		Grants: []RotationGrant{{ID: grant, GroupID: group, Version: 1, Wrapped: base64.StdEncoding.EncodeToString(make([]byte, 256)), Policy: GrantPolicyLegacy}}}
	d, err := r.Commitment(account, strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	if d.GrantsDigest != "bf90a5272636e084da5b9f1d85ba146354c52453ffdc59b4de34ba316b88cbd1" || d.SharesDigest != "9e6955eaab4c14dc07920627ff32598734ff3be2ea84dacc2fa2dcb67afe183f" || d.RequestDigest != "1d2345cfafb9c19303ae5b74a399314e66cd24f519a8ae782119d919685bce6e" {
		t.Fatal("request digest vector differs")
	}
	d.Challenge = "challenge"
	d.DeviceID = device
	d.TokenID = account
	d.SessionStart = 123
	d.IssuedAt = 100
	d.ExpiresAt = 110
	d.Version = 1
	if fmt.Sprintf("%x", sha256.Sum256([]byte(d.Canonical()))) != "ec9ccedf0921299b67fce9ceec66cfbe5fabb550d2def169d032431e8c1834fc" {
		t.Fatal("decision canonical differs")
	}
	f := ArchiveSplitFinalizationReceipt{Kind: "reconfiguration", OperationID: op, OrgID: org, ArchiveKeySPKIFingerprint: strings.Repeat("1", 64), TargetKeySPKIFingerprint: strings.Repeat("2", 64), SourceConfigDigest: strings.Repeat("3", 64), ConfigDigest: strings.Repeat("4", 64), SharesDigest: strings.Repeat("5", 64), GrantsDigest: strings.Repeat("6", 64), FinalizedAt: 100, ServerKeyVersion: 1}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(ArchiveSplitFinalizationReceiptCanonical(f)))) != "9198e5ec0ae99c9d22ea84ec004d000c568660ddb561361bcb44317dbc48176a" {
		t.Fatal("finalization canonical differs")
	}
}
