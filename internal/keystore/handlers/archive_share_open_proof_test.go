package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	proofTestPerson = "bbbbbbbb-1111-4111-8111-111111111111"
	proofTestNonce  = "Tm9uY2VOb25jZU5vbmNlTm9uY2VOb25jZU5vbmNlTm8"
)

type proofFixture struct {
	*splitFixture
	shares  []proto.WrappedShare
	request proto.ArchiveShareOpenProofRequest
	reads   *archivePrivateReadProbe
}

// newProofFixture splits a real archive key and makes this Keeper the
// participant holding share 2 under its account archive key.
func newProofFixture(t *testing.T) *proofFixture {
	t.Helper()
	sf := newSplitFixture(t)
	response := HandleArchiveKeySplit(sf.deps, sf.authorize(t, sf.request))
	if !response.Success {
		t.Fatalf("authorized split refused: %s", response.Error)
	}
	shares := response.Data.(proto.ArchiveKeySplitResponseData).Shares
	if err := keychain.SaveAccountArchivePrivateKey(sf.store, sf.admins[1].PrivateKey); err != nil {
		t.Fatal(err)
	}
	share := shares[1]
	f := &proofFixture{splitFixture: sf, shares: shares, request: proto.ArchiveShareOpenProofRequest{
		AccountID: sf.v.AccountID, OrgID: sf.v.OrgID, OperationID: splitTestOperation, ConfigDigest: splitTestConfig,
		ShareIndex: share.ShareIndex, WrappedKey: share.WrappedKey, Ciphertext: share.Ciphertext,
		ProofPublicKey: share.ProofPublicKey,
	}}
	f.reads = &archivePrivateReadProbe{SecretStore: sf.store}
	f.deps.Store = f.reads
	return f
}

func (f *proofFixture) authorizeProof(t *testing.T, req proto.ArchiveShareOpenProofRequest) proto.ArchiveShareOpenProofRequest {
	t.Helper()
	req.Decision = nil
	response := HandleArchiveShareProofPrepare(f.deps, proto.ArchiveShareProofPrepareRequest{Request: req, TokenID: splitTestToken, SessionIssuedAtNanos: 123})
	if !response.Success {
		t.Fatalf("valid proof preparation refused: %s %s", response.ErrorCode, response.Error)
	}
	prepared := response.Data.(proto.ArchiveShareProofPrepareResponseData)
	now := f.clock.now().Unix()
	decision := proto.ArchiveShareOpenProofDecision{
		Challenge: prepared.Challenge, AccountID: req.AccountID, DeviceID: splitTestDevice, TokenID: splitTestToken,
		SessionIssuedAtNanos: 123, OrgID: req.OrgID, OperationID: req.OperationID, ConfigDigest: req.ConfigDigest,
		ArchiveKeySPKIFingerprint: strings.Repeat("5a", 32), PersonID: proofTestPerson, ShareIndex: req.ShareIndex,
		ShareDigest:    proto.ArchiveShareEnvelopeDigest(req.ShareIndex, req.WrappedKey, req.Ciphertext),
		ProofPublicKey: req.ProofPublicKey, ServerNonce: proofTestNonce, RequestDigest: prepared.RequestDigest,
		IssuedAt: now, ExpiresAt: now + proto.ArchiveShareDecisionTTLSeconds, ServerKeyVersion: 1,
	}
	decision.Signature = f.sign(t, proto.ArchiveShareOpenProofDecisionCanonical(decision))
	req.Decision = &decision
	return req
}

func (f *proofFixture) resignProof(t *testing.T, req proto.ArchiveShareOpenProofRequest) {
	t.Helper()
	req.Decision.Signature = f.sign(t, proto.ArchiveShareOpenProofDecisionCanonical(*req.Decision))
}

func lp(fields ...string) string {
	var b strings.Builder
	for _, field := range fields {
		b.WriteString("|" + strconv.Itoa(len(field)) + ":" + field)
	}
	return b.String()
}

func TestArchiveShareOpenProofSignsWithShareDerivedKeyAndReturnsOnlySignature(t *testing.T) {
	f := newProofFixture(t)
	req := f.authorizeProof(t, f.request)
	response := HandleArchiveShareOpenProof(f.deps, req)
	if !response.Success {
		t.Fatalf("valid proof refused: %s %s", response.ErrorCode, response.Error)
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 1 || fields["signature"] == nil {
		t.Fatalf("proof response carries more than the signature: %s", encoded)
	}
	signature, err := base64.StdEncoding.DecodeString(response.Data.(proto.ArchiveShareOpenProofResponseData).Signature)
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(req.ProofPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d := req.Decision
	// Rebuilt from the plan's field list, independent of the proto helpers.
	envelope := sha256.Sum256([]byte("dragpass.archive.share.envelope|1" + lp(strconv.Itoa(req.ShareIndex), req.WrappedKey, req.Ciphertext)))
	if d.ShareDigest != hex.EncodeToString(envelope[:]) {
		t.Fatal("share digest encoding changed")
	}
	statement := "dragpass.archive.share.open-proof|1" + lp(d.ServerNonce, d.OperationID, d.ConfigDigest,
		d.ArchiveKeySPKIFingerprint, d.OrgID, d.PersonID, d.AccountID, d.DeviceID, strconv.Itoa(d.ShareIndex),
		d.ShareDigest, d.ProofPublicKey, strconv.FormatInt(d.ExpiresAt, 10))
	if !ed25519.Verify(ed25519.PublicKey(public), []byte(statement), signature) {
		t.Fatal("proof signature does not verify under the share's proof public key")
	}
	if f.reads.reads != 1 {
		t.Fatalf("account archive key reads = %d", f.reads.reads)
	}
}

func TestArchiveShareOpenProofRefusesInvalidDecisionBeforeAccountKeyRead(t *testing.T) {
	type mutation func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest)
	resign := func(change func(d *proto.ArchiveShareOpenProofDecision)) mutation {
		return func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			change(req.Decision)
			f.resignProof(t, *req)
		}
	}
	other := strings.Repeat("ab", 32)
	cases := map[string]mutation{
		"missing": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) { req.Decision = nil },
		"forged": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.Decision.Signature = "AA=="
		},
		"other domain": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.Decision.Signature = f.sign(t, proto.ArchiveSplitDecisionCanonical(proto.ArchiveSplitDecision{}))
		},
		"expired":              func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) { f.clock.advance(11) },
		"unprepared challenge": resign(func(d *proto.ArchiveShareOpenProofDecision) { d.Challenge = strings.Repeat("A", 43) }),
		"account": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.AccountID, req.Decision.AccountID = splitTestOther, splitTestOther
			f.resignProof(t, *req)
		},
		"device":  resign(func(d *proto.ArchiveShareOpenProofDecision) { d.DeviceID = splitTestOther }),
		"token":   resign(func(d *proto.ArchiveShareOpenProofDecision) { d.TokenID = splitTestOther }),
		"session": resign(func(d *proto.ArchiveShareOpenProofDecision) { d.SessionIssuedAtNanos = 124 }),
		"live device": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			if err := f.store.Set(config.Service, config.DeviceID, splitTestOther); err != nil {
				t.Fatal(err)
			}
		},
		"signed out": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			if _, _, err := keychain.SetAccountBinding(f.store, req.AccountID, "test", true); err != nil {
				t.Fatal(err)
			}
		},
		"operation": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.OperationID, req.Decision.OperationID = splitTestOther, splitTestOther
			f.resignProof(t, *req)
		},
		"org":            resign(func(d *proto.ArchiveShareOpenProofDecision) { d.OrgID = splitTestOther }),
		"config digest":  resign(func(d *proto.ArchiveShareOpenProofDecision) { d.ConfigDigest = other }),
		"share index":    resign(func(d *proto.ArchiveShareOpenProofDecision) { d.ShareIndex = 3 }),
		"share digest":   resign(func(d *proto.ArchiveShareOpenProofDecision) { d.ShareDigest = other }),
		"request digest": resign(func(d *proto.ArchiveShareOpenProofDecision) { d.RequestDigest = other }),
		"decision proof key": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.Decision.ProofPublicKey = f.shares[0].ProofPublicKey
			f.resignProof(t, *req)
		},
		"changed envelope": func(t *testing.T, f *proofFixture, req *proto.ArchiveShareOpenProofRequest) {
			req.WrappedKey, req.Ciphertext = f.shares[0].WrappedKey, f.shares[0].Ciphertext
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newProofFixture(t)
			req := f.authorizeProof(t, f.request)
			mutate(t, f, &req)
			response := HandleArchiveShareOpenProof(f.deps, req)
			if response.Success || response.Data != nil || f.reads.reads != 0 {
				t.Fatalf("invalid proof authority reached the account archive key or returned output (reads=%d)", f.reads.reads)
			}
		})
	}
}

func TestArchiveShareOpenProofRefusesReplay(t *testing.T) {
	f := newProofFixture(t)
	req := f.authorizeProof(t, f.request)
	if first := HandleArchiveShareOpenProof(f.deps, req); !first.Success {
		t.Fatalf("valid proof refused: %s", first.Error)
	}
	if replay := HandleArchiveShareOpenProof(f.deps, req); replay.Success || replay.Data != nil || f.reads.reads != 1 {
		t.Fatal("replayed proof decision reached the account archive key again")
	}
}

// The server signs a proof public key that is not this share's: opening the
// share and re-deriving the key must refuse rather than sign.
func TestArchiveShareOpenProofRefusesMismatchedProofPublicKey(t *testing.T) {
	f := newProofFixture(t)
	req := f.request
	req.ProofPublicKey = f.shares[0].ProofPublicKey
	req = f.authorizeProof(t, req)
	response := HandleArchiveShareOpenProof(f.deps, req)
	if response.Success || response.Data != nil {
		t.Fatal("signed with a proof key the share does not derive")
	}
	if response.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("error code = %q", response.ErrorCode)
	}
}

// A share index that is not the one embedded in the share is refused even
// when the server signed it.
func TestArchiveShareOpenProofRefusesEmbeddedIndexMismatch(t *testing.T) {
	f := newProofFixture(t)
	req := f.request
	req.ShareIndex = f.shares[2].ShareIndex
	req.ProofPublicKey = f.shares[2].ProofPublicKey
	req = f.authorizeProof(t, req)
	if response := HandleArchiveShareOpenProof(f.deps, req); response.Success || response.Data != nil {
		t.Fatal("proof accepted a share index that is not embedded in the share")
	}
}

func TestArchiveShareOpenProofWithholdsLateSignature(t *testing.T) {
	f := newProofFixture(t)
	req := f.authorizeProof(t, f.request)
	f.reads.beforeRead = func() { f.clock.advance(11) }
	if response := HandleArchiveShareOpenProof(f.deps, req); response.Success || response.Data != nil {
		t.Fatal("proof signature returned after its decision expired")
	}
}

func TestArchiveShareProofPrepareRefusesOtherAccount(t *testing.T) {
	f := newProofFixture(t)
	req := f.request
	req.AccountID = splitTestOther
	response := HandleArchiveShareProofPrepare(f.deps, proto.ArchiveShareProofPrepareRequest{Request: req, TokenID: splitTestToken, SessionIssuedAtNanos: 123})
	if response.Success || f.deps.ArchiveProofChallenges.Len() != 0 || f.reads.reads != 0 {
		t.Fatal("proof preparation accepted another account's request")
	}
}

// A split challenge cannot satisfy a proof decision: the stores are separate.
func TestArchiveShareOpenProofRefusesSplitChallenge(t *testing.T) {
	f := newProofFixture(t)
	split := f.authorize(t, f.splitFixture.request)
	req := f.authorizeProof(t, f.request)
	req.Decision.Challenge = split.Decision.Challenge
	f.resignProof(t, req)
	if response := HandleArchiveShareOpenProof(f.deps, req); response.Success || f.reads.reads != 0 {
		t.Fatal("a split challenge satisfied a proof decision")
	}
}
