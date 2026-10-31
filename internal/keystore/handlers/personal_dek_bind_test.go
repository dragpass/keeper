package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func personalBindingFixture(t *testing.T) (Deps, *testdouble.MemorySecretStore, proto.PersonalDEKBindRequest, *rsa.PrivateKey) {
	t.Helper()
	d, _, store := newTestDeps(t)
	now := time.Unix(1793440000, 0)
	d.Clock = func() time.Time { return now }
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	d.ServerKeyVerifier = msgTestVerifier{version: 1, public: &serverKey.PublicKey}
	const account = "11111111-1111-4111-8111-111111111111"
	const device = "22222222-2222-4222-8222-222222222222"
	_, _, err = keychain.EnsureDeviceID(store, func() (string, keychain.DeviceIDSource, error) { return device, keychain.DeviceIDCandidate, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.PrepareChatLogin(store, "AAAAAAAAAAAAAAAAAAAAAA", "", 0); err != nil {
		t.Fatal(err)
	}
	login, _, err := keychain.CommitChatLogin(store, "AAAAAAAAAAAAAAAAAAAAAA", account, "alice")
	if err != nil {
		t.Fatal(err)
	}
	setKeychainDeviceKey(t, store, make([]byte, 32))
	const password = "binding-test-password"
	signup := signupDEKForTest(d, password)
	if !signup.Success {
		t.Fatal("fixture signup failed")
	}
	wrap := signup.Data.(proto.DEKGenerateAndWrapDualResponseData).PasswordWrappedDEKB64
	restored := HandleDEKRotateToDeviceKey(d, proto.DEKRotateToDeviceKeyRequest{Password: password, EncryptedDEKB64: wrap})
	if !restored.Success {
		t.Fatal("fixture restore failed")
	}
	raw, _ := base64.StdEncoding.DecodeString(wrap)
	digest := sha256.Sum256(raw)
	proof := proto.PersonalDEKBindingProof{AccountID: account, DeviceID: device, TokenID: "33333333-3333-4333-8333-333333333333", SessionIssuedAtNanos: now.UnixNano(), LoginGeneration: login.Generation, WrappedDEKDigest: hex.EncodeToString(digest[:]), IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 30, ServerKeyVersion: 1}
	signature, err := crypto.SignData(serverKey, proto.PersonalDEKBindingCanonical(proof))
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature = base64.StdEncoding.EncodeToString(signature)
	return d, store, proto.PersonalDEKBindRequest{Password: password, EncryptedDEKB64: wrap, Proof: proof}, serverKey
}

func TestPersonalDEKBindStoresOnlyVerifiedProvenance(t *testing.T) {
	d, store, req, _ := personalBindingFixture(t)
	response := HandlePersonalDEKBind(d, req)
	if !response.Success {
		t.Fatal("valid provenance was not bound")
	}
	value, err := store.Get(config.Service, "personal_dek_provenance_v1")
	if err != nil || value == "" {
		t.Fatal("provenance not stored")
	}
}

func TestPersonalDEKLegacySlotWriteInvalidatesProvenance(t *testing.T) {
	d, store, req, _ := personalBindingFixture(t)
	if !HandlePersonalDEKBind(d, req).Success {
		t.Fatal("bind failed")
	}
	if _, err := keychain.ReadPersonalDEKProvenance(store); err != nil {
		t.Fatal("verified provenance unavailable")
	}
	wrapped, err := keychain.GetPersonalDeviceWrappedDEK(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePersonalDeviceWrappedDEK(store, wrapped); err != nil {
		t.Fatal(err)
	}
	if _, err := keychain.ReadPersonalDEKProvenance(store); err == nil {
		t.Fatal("legacy slot write retained verified provenance")
	}
}

func TestPersonalDEKBindRejectsMismatchedOrStaleEvidence(t *testing.T) {
	for _, name := range []string{"wrap substitution", "wrong local DEK", "signed account mismatch", "signed device mismatch", "signature tampering", "expired", "new login", "signed out", "wrong password", "storage failure"} {
		t.Run(name, func(t *testing.T) {
			d, store, req, key := personalBindingFixture(t)
			resign := false
			switch name {
			case "wrap substitution":
				req.EncryptedDEKB64 = base64.StdEncoding.EncodeToString(make([]byte, 76))
			case "wrong local DEK":
				if !signupDEKForTest(d, req.Password).Success {
					t.Fatal("replacement fixture failed")
				}
			case "signed account mismatch":
				req.Proof.AccountID = "44444444-4444-4444-8444-444444444444"
				resign = true
			case "signed device mismatch":
				req.Proof.DeviceID = "44444444-4444-4444-8444-444444444444"
				resign = true
			case "signature tampering":
				req.Proof.SessionIssuedAtNanos++
			case "expired":
				d.Clock = func() time.Time { return time.Unix(req.Proof.ExpiresAt, 0) }
			case "new login":
				if err := keychain.PrepareChatLogin(store, "BBBBBBBBBBBBBBBBBBBBBA", req.Proof.LoginGeneration, 1); err != nil {
					t.Fatal(err)
				}
				if _, _, err := keychain.CommitChatLogin(store, "BBBBBBBBBBBBBBBBBBBBBA", req.Proof.AccountID, "alice"); err != nil {
					t.Fatal(err)
				}
			case "signed out":
				if _, _, err := keychain.SignOutAccountBinding(store); err != nil {
					t.Fatal(err)
				}
			case "wrong password":
				req.Password = "not-the-password"
			case "storage failure":
				d.Store = personalProofFailStore{SecretStore: store}
			}
			if resign {
				sig, err := crypto.SignData(key, proto.PersonalDEKBindingCanonical(req.Proof))
				if err != nil {
					t.Fatal(err)
				}
				req.Proof.Signature = base64.StdEncoding.EncodeToString(sig)
			}
			if HandlePersonalDEKBind(d, req).Success {
				t.Fatal("invalid binding accepted")
			}
			if _, err := keychain.ReadPersonalDEKProvenance(store); err == nil {
				t.Fatal("invalid binding left usable provenance")
			}
		})
	}
}

type personalProofFailStore struct{ keychain.SecretStore }

func (s personalProofFailStore) Set(service, account, value string) error {
	if account == "personal_dek_provenance_v1" {
		return errors.New("injected storage failure")
	}
	return s.SecretStore.Set(service, account, value)
}

func TestPersonalDEKProvenanceCannotOutliveLocalIdentity(t *testing.T) {
	for _, event := range []string{"new login", "signout", "device key change", "slot deletion"} {
		t.Run(event, func(t *testing.T) {
			d, store, req, _ := personalBindingFixture(t)
			if !HandlePersonalDEKBind(d, req).Success {
				t.Fatal("bind failed")
			}
			if _, err := keychain.ReadPersonalDEKProvenance(store); err != nil {
				t.Fatal("bound record unavailable")
			}
			switch event {
			case "new login":
				if err := keychain.PrepareChatLogin(store, "BBBBBBBBBBBBBBBBBBBBBA", req.Proof.LoginGeneration, 1); err != nil {
					t.Fatal(err)
				}
				if _, _, err := keychain.CommitChatLogin(store, "BBBBBBBBBBBBBBBBBBBBBA", req.Proof.AccountID, "alice"); err != nil {
					t.Fatal(err)
				}
			case "signout":
				if _, _, err := keychain.SignOutAccountBinding(store); err != nil {
					t.Fatal(err)
				}
			case "device key change":
				setKeychainDeviceKey(t, store, bytes.Repeat([]byte{1}, 32))
			case "slot deletion":
				if err := keychain.DeletePersonalDeviceWrappedDEK(store); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := keychain.ReadPersonalDEKProvenance(store); err == nil {
				t.Fatal("stale local provenance remained usable")
			}
		})
	}
}

func TestPersonalDEKBindCannotReplaceServerSessionWithinOneLocalLogin(t *testing.T) {
	d, store, req, key := personalBindingFixture(t)
	if !HandlePersonalDEKBind(d, req).Success {
		t.Fatal("bind failed")
	}
	original, err := keychain.ReadPersonalDEKProvenance(store)
	if err != nil {
		t.Fatal(err)
	}
	req.Proof.SessionIssuedAtNanos++
	signature, err := crypto.SignData(key, proto.PersonalDEKBindingCanonical(req.Proof))
	if err != nil {
		t.Fatal(err)
	}
	req.Proof.Signature = base64.StdEncoding.EncodeToString(signature)
	if HandlePersonalDEKBind(d, req).Success {
		t.Fatal("another server login replaced bound session")
	}
	current, err := keychain.ReadPersonalDEKProvenance(store)
	if err != nil {
		t.Fatal(err)
	}
	if current != original {
		t.Fatal("refusal changed original provenance")
	}
}
