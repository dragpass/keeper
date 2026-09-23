// Tests for HandleMLSLeafDeclare and VerifyLeafDeclaration.
//
// The verifier cases are the rows of design §11 V3 that can be judged without
// MLS: A1 (no declaration), A2 (forged signature), A3 (another account's
// declaration), and A5's `compromise` reason, plus the fingerprint, device_id
// and public key substitutions §5.3 step 5 exists to catch. A4 is the pin state
// machine's and is covered by peer_key_trust_test.go.
package handlers

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	leafTestAccountID = "11111111-1111-4111-8111-111111111111"
	leafTestDeviceID  = "44444444-4444-4444-8444-444444444444"
)

const leafTestNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func leafChallenge(accountID, deviceID string, expiresAt int64) string {
	return "dragpass.mls.leaf.challenge|1|" + accountID + "|" + deviceID + "|" + leafTestNonce + "|" +
		strconv.FormatInt(expiresAt, 10)
}

func leafDeclareRequest(reason string) proto.MLSLeafDeclareRequest {
	req := proto.MLSLeafDeclareRequest{
		ServerSignature: "any",
		AccountID:       leafTestAccountID,
		DeviceID:        leafTestDeviceID,
		NotBefore:       time.Now().Unix(),
		Reason:          reason,
	}
	return withLeafChallenge(req)
}

// withLeafChallenge re-issues the challenge for whatever identity req names,
// so tests that change the identity exercise the key check, not the gate.
func withLeafChallenge(req proto.MLSLeafDeclareRequest) proto.MLSLeafDeclareRequest {
	req.ChallengeToken = leafChallenge(req.AccountID, req.DeviceID, time.Now().Unix()+proto.MLSLeafChallengeTTLSeconds)
	return req
}

func accountPublicKey(t *testing.T, pemText string) *rsa.PublicKey {
	t.Helper()
	pub, err := crypto.ParsePublicKey(pemText)
	if err != nil {
		t.Fatalf("parse account public key: %v", err)
	}
	return pub
}

func declareLeaf(t *testing.T, deps Deps, req proto.MLSLeafDeclareRequest) proto.MLSLeafDeclaration {
	t.Helper()
	resp := HandleMLSLeafDeclare(deps, req)
	if !resp.Success {
		t.Fatalf("mls_leaf_declare(%s) failed: %s", req.Reason, resp.Error)
	}
	return resp.Data.(proto.MLSLeafDeclareResponseData).MLSLeafDeclaration
}

func storedLeafKey(t *testing.T, store keychain.SecretStore) keychain.MLSLeafKey {
	t.Helper()
	key, found, err := keychain.GetMLSLeafKey(store)
	if err != nil || !found {
		t.Fatalf("stored leaf key: found=%v err=%v", found, err)
	}
	return key
}

func TestHandleMLSLeafDeclare_EnrollSignsAVerifiableDeclaration(t *testing.T) {
	deps, log, store := newTestDeps(t)
	accountPub, _ := seedActiveKeypairForRotateTest(t, store)

	decl := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	if err := VerifyLeafDeclaration(decl, accountPublicKey(t, accountPub)); err != nil {
		t.Fatalf("declaration does not verify under the account key: %v", err)
	}
	if decl.AccountID != leafTestAccountID || decl.DeviceID != leafTestDeviceID || decl.Reason != proto.MLSLeafReasonEnroll {
		t.Fatalf("declaration fields do not echo the request: %+v", decl)
	}

	key := storedLeafKey(t, store)
	if decl.SignatureKey != base64.StdEncoding.EncodeToString(key.PublicKey) {
		t.Fatal("declared signature_key is not the stored leaf public key")
	}
	if key.AccountID != leafTestAccountID || key.DeviceID != leafTestDeviceID {
		t.Fatal("stored leaf key does not name the declared account and device")
	}
	secretB64 := base64.StdEncoding.EncodeToString(key.SecretKey)
	seedB64 := base64.StdEncoding.EncodeToString(key.SecretKey[:ed25519.SeedSize])
	for _, leaked := range []string{secretB64, seedB64} {
		if log.Contains(leaked) || strings.Contains(decl.Signature+decl.SignatureKey, leaked) {
			t.Fatal("leaf secret key reached the log or the response")
		}
	}
}

func TestHandleMLSLeafDeclare_EnrollAgainKeepsTheKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	accountPub, _ := seedActiveKeypairForRotateTest(t, store)

	first := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	second := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	if first.SignatureKey != second.SignatureKey {
		t.Fatal("a repeated enroll minted a new key")
	}
	if err := VerifyLeafDeclaration(second, accountPublicKey(t, accountPub)); err != nil {
		t.Fatalf("repeated enroll declaration does not verify: %v", err)
	}
}

func TestHandleMLSLeafDeclare_RotateReplacesTheStoredKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	accountPub, _ := seedActiveKeypairForRotateTest(t, store)

	enrolled := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	oldKey := storedLeafKey(t, store)
	oldSecretB64 := base64.StdEncoding.EncodeToString(oldKey.SecretKey)

	rotated := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonRotate))

	if rotated.SignatureKey == enrolled.SignatureKey || rotated.SignatureKeyFingerprint == enrolled.SignatureKeyFingerprint {
		t.Fatal("rotate declared the old key")
	}
	if rotated.Reason != proto.MLSLeafReasonRotate {
		t.Fatalf("reason = %q, want rotate", rotated.Reason)
	}
	if err := VerifyLeafDeclaration(rotated, accountPublicKey(t, accountPub)); err != nil {
		t.Fatalf("rotate declaration does not verify: %v", err)
	}
	newKey := storedLeafKey(t, store)
	if rotated.SignatureKey != base64.StdEncoding.EncodeToString(newKey.PublicKey) {
		t.Fatal("stored key is not the one the rotate declared")
	}
	raw, err := store.Get(config.Service, config.MLSLeafSignatureKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, oldSecretB64) {
		t.Fatal("the old leaf secret key survived the rotation")
	}
}

func TestHandleMLSLeafDeclare_RotateWithoutEnrollIsNotFound(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)

	resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate))
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("rotate with no key = %+v, want not_found", resp)
	}
	if _, found, _ := keychain.GetMLSLeafKey(store); found {
		t.Fatal("a refused rotate stored a key")
	}
}

func TestHandleMLSLeafDeclare_RefusesToRebindAnotherDevicesKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	enrolled := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	for _, reason := range []string{proto.MLSLeafReasonEnroll, proto.MLSLeafReasonRotate} {
		otherDevice := leafDeclareRequest(reason)
		otherDevice.DeviceID = "55555555-5555-4555-8555-555555555555"
		otherAccount := leafDeclareRequest(reason)
		otherAccount.AccountID = "22222222-2222-4222-8222-222222222222"
		for _, req := range []proto.MLSLeafDeclareRequest{otherDevice, otherAccount} {
			if resp := HandleMLSLeafDeclare(deps, withLeafChallenge(req)); resp.Success {
				t.Fatalf("%s for a different identity succeeded", reason)
			}
		}
	}
	if storedLeafKey(t, store).DeviceID != leafTestDeviceID ||
		base64.StdEncoding.EncodeToString(storedLeafKey(t, store).PublicKey) != enrolled.SignatureKey {
		t.Fatal("a refused request changed the stored key")
	}
}

func TestHandleMLSLeafDeclare_GatesBeforeTouchingTheKey(t *testing.T) {
	t.Run("server signature", func(t *testing.T) {
		deps, _, store := newTestDepsFailVerify(t, errors.New("server signature verification failed: stub"))
		seedActiveKeypairForRotateTest(t, store)
		if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll)); resp.Success {
			t.Fatal("declare succeeded with a rejected server signature")
		}
		if _, found, _ := keychain.GetMLSLeafKey(store); found {
			t.Fatal("a key was stored before the server signature verified")
		}
	})
	t.Run("future not_before", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		seedActiveKeypairForRotateTest(t, store)
		req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
		req.NotBefore = time.Now().Unix() + proto.KeyRotationPrepareMaxFutureSeconds + 60
		if resp := HandleMLSLeafDeclare(deps, req); resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("future not_before = %+v, want validation_error", resp)
		}
	})
	t.Run("no account key", func(t *testing.T) {
		deps, _, store := newTestDeps(t)
		if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonEnroll)); resp.Success {
			t.Fatal("declare succeeded without an account keypair")
		}
		if _, found, _ := keychain.GetMLSLeafKey(store); found {
			t.Fatal("a key was stored with nothing to declare it under")
		}
	})
}

// Every token here carries a valid server signature (the verifier passes); what
// is refused is a token not issued for this declaration. The enrolled key must
// come through each refusal byte for byte.
func TestHandleMLSLeafDeclare_ChallengeIsBoundToPurposeAndIdentity(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))
	before, err := store.Get(config.Service, config.MLSLeafSignatureKey)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	valid := now + proto.MLSLeafChallengeTTLSeconds
	otherID := "55555555-5555-4555-8555-555555555555"
	refused := map[string]string{
		"rotation challenge":   "rotate-challenge-001",
		"other domain":         "dragpass.keyrotation|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|" + strconv.FormatInt(valid, 10),
		"version 2":            "dragpass.mls.leaf.challenge|2|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|" + strconv.FormatInt(valid, 10),
		"extra field":          leafChallenge(leafTestAccountID, leafTestDeviceID, valid) + "|x",
		"short nonce":          "dragpass.mls.leaf.challenge|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|abcd|" + strconv.FormatInt(valid, 10),
		"padded expiry":        "dragpass.mls.leaf.challenge|1|" + leafTestAccountID + "|" + leafTestDeviceID + "|" + leafTestNonce + "|0" + strconv.FormatInt(valid, 10),
		"other account":        leafChallenge(otherID, leafTestDeviceID, valid),
		"other device":         leafChallenge(leafTestAccountID, otherID, valid),
		"expired":              leafChallenge(leafTestAccountID, leafTestDeviceID, now-1),
		"expires now":          leafChallenge(leafTestAccountID, leafTestDeviceID, now),
		"issued in the future": leafChallenge(leafTestAccountID, leafTestDeviceID, now+proto.MLSLeafChallengeTTLSeconds+mlsLeafChallengeClockSkewSeconds+60),
	}
	for _, reason := range []string{proto.MLSLeafReasonEnroll, proto.MLSLeafReasonRotate} {
		for name, token := range refused {
			req := leafDeclareRequest(reason)
			req.ChallengeToken = token
			if resp := HandleMLSLeafDeclare(deps, req); resp.Success {
				t.Errorf("%s/%s: accepted", reason, name)
			}
			after, err := store.Get(config.Service, config.MLSLeafSignatureKey)
			if err != nil || after != before {
				t.Fatalf("%s/%s: the keyring slot changed on a refused challenge", reason, name)
			}
		}
	}

	if resp := HandleMLSLeafDeclare(deps, leafDeclareRequest(proto.MLSLeafReasonRotate)); !resp.Success {
		t.Fatalf("a correctly formed challenge was refused: %s", resp.Error)
	}
}

func TestHandleMLSLeafDeclare_RefusedChallengeCreatesNoKey(t *testing.T) {
	deps, _, store := newTestDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	req := leafDeclareRequest(proto.MLSLeafReasonEnroll)
	req.ChallengeToken = leafChallenge(leafTestAccountID, leafTestDeviceID, time.Now().Unix()-1)
	if resp := HandleMLSLeafDeclare(deps, req); resp.Success {
		t.Fatal("expired challenge accepted")
	}
	if _, err := store.Get(config.Service, config.MLSLeafSignatureKey); err == nil {
		t.Fatal("a refused challenge created a key")
	}
}

func TestResetDeviceIdentity_RemovesTheMLSLeafKey(t *testing.T) {
	deps, _, store := newResetDeps(t)
	seedActiveKeypairForRotateTest(t, store)
	declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	resp := HandleResetDeviceIdentity(deps, proto.ResetDeviceIdentityRequest{})
	if !resp.Success {
		t.Fatalf("reset failed: %s", resp.Error)
	}
	found := false
	for _, name := range clearedList(t, resp) {
		found = found || name == config.MLSLeafSignatureKey
	}
	if !found {
		t.Fatalf("cleared = %v, want it to name %s", clearedList(t, resp), config.MLSLeafSignatureKey)
	}
	if _, ok, _ := keychain.GetMLSLeafKey(store); ok {
		t.Fatal("leaf key survived the reset")
	}
}

// ────────────────────────────────────────────────────────────────────────
// VerifyLeafDeclaration
// ────────────────────────────────────────────────────────────────────────

func TestVerifyLeafDeclaration_RefusesEverySubstitution(t *testing.T) {
	deps, _, store := newTestDeps(t)
	accountPubPEM, _ := seedActiveKeypairForRotateTest(t, store)
	accountPub := accountPublicKey(t, accountPubPEM)
	good := declareLeaf(t, deps, leafDeclareRequest(proto.MLSLeafReasonEnroll))

	otherAccount, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub := accountPublicKey(t, otherAccount.PublicKey)

	attackerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerFP, err := crypto.MLSLeafSignatureKeyFingerprint(attackerPub)
	if err != nil {
		t.Fatal(err)
	}

	signedByOther := good
	signedByOther.Signature, err = signWithPEM(otherAccount.PrivateKey, good.Canonical())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		decl proto.MLSLeafDeclaration
		key  *rsa.PublicKey
	}{
		"A1 no declaration":               {proto.MLSLeafDeclaration{}, accountPub},
		"A2 forged signature":             {withSignature(good, base64.StdEncoding.EncodeToString(make([]byte, 256))), accountPub},
		"A2 another account's key signed": {signedByOther, accountPub},
		"A3 another account's decl":       {good, otherPub},
		"account_id swapped":              {withAccount(good, "22222222-2222-4222-8222-222222222222"), accountPub},
		"device_id swapped":               {withDevice(good, "55555555-5555-4555-8555-555555555555"), accountPub},
		"wrong fingerprint":               {withFingerprint(good, attackerFP), accountPub},
		"tampered public key":             {withKey(good, attackerPub), accountPub},
		"tampered key and fingerprint":    {withFingerprint(withKey(good, attackerPub), attackerFP), accountPub},
		"key not 32 bytes":                {withKeyBytes(good, append(attackerPub, 0)), accountPub},
		"A5 compromise reason":            {withReason(good, "compromise"), accountPub},
		"unknown reason":                  {withReason(good, "revoke"), accountPub},
		"rotate relabelled":               {withReason(good, proto.MLSLeafReasonRotate), accountPub},
		"not_before moved":                {withNotBefore(good, good.NotBefore+1), accountPub},
		"no account key":                  {good, nil},
	}
	for name, c := range cases {
		if err := VerifyLeafDeclaration(c.decl, c.key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := VerifyLeafDeclaration(good, accountPub); err != nil {
		t.Fatalf("the untouched declaration stopped verifying: %v", err)
	}
}

func signWithPEM(privatePEM, canonical string) (string, error) {
	priv, err := crypto.ParsePrivateKey(privatePEM)
	if err != nil {
		return "", err
	}
	sig, err := crypto.SignData(priv, canonical)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func withSignature(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.Signature = v
	return d
}

func withAccount(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.AccountID = v
	return d
}

func withDevice(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.DeviceID = v
	return d
}

func withFingerprint(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.SignatureKeyFingerprint = v
	return d
}

func withKey(d proto.MLSLeafDeclaration, v ed25519.PublicKey) proto.MLSLeafDeclaration {
	return withKeyBytes(d, v)
}

func withKeyBytes(d proto.MLSLeafDeclaration, v []byte) proto.MLSLeafDeclaration {
	d.SignatureKey = base64.StdEncoding.EncodeToString(v)
	return d
}

func withReason(d proto.MLSLeafDeclaration, v string) proto.MLSLeafDeclaration {
	d.Reason = v
	return d
}

func withNotBefore(d proto.MLSLeafDeclaration, v int64) proto.MLSLeafDeclaration {
	d.NotBefore = v
	return d
}

// A signature over the literal ariadne pins must verify here, so a canonical
// the two sides build differently cannot pass both suites.
func TestVerifyLeafDeclaration_GoldenCanonicalRoundTrip(t *testing.T) {
	const golden = "dragpass.mls.leaf|1|11111111-1111-4111-8111-111111111111|44444444-4444-4444-8444-444444444444|66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925|1788999000|enroll"
	account, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signWithPEM(account.PrivateKey, golden)
	if err != nil {
		t.Fatal(err)
	}
	decl := proto.MLSLeafDeclaration{
		AccountID:               leafTestAccountID,
		DeviceID:                leafTestDeviceID,
		SignatureKey:            base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		SignatureKeyFingerprint: "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
		NotBefore:               1788999000,
		Reason:                  proto.MLSLeafReasonEnroll,
		Signature:               signature,
	}
	if err := VerifyLeafDeclaration(decl, accountPublicKey(t, account.PublicKey)); err != nil {
		t.Fatalf("declaration signed over the golden literal does not verify: %v", err)
	}
}
