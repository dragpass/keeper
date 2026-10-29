package onlineauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

type testVerifier struct{ reject bool }

func (v testVerifier) Verify(message, signature string, version uint) error {
	if v.reject || signature != "signed" || version != 3 || message == "" {
		return errors.New("invalid signature")
	}
	return nil
}

func testIdentity() Identity {
	return Identity{
		AccountID: "account", DeviceID: "device", SessionStartNanos: 42,
		AppBinding: "binding", ConversationID: "conversation", OrgID: "org",
		LocalSession: "local-session", LoginGeneration: "generation",
	}
}

func testDecision(challenge, commitment string, now time.Time) Decision {
	return Decision{
		Action: "mls_decrypt_batch_for_app_display", Challenge: challenge,
		Commitment: commitment, AccountID: "account", DeviceID: "device",
		SessionStartNanos: 42, AppBinding: "binding",
		ConversationID: "conversation", OrgID: "org",
		IssuedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(15 * time.Second).UnixMilli(),
		ServerKeyVersion: 3, Signature: "signed",
	}
}

func TestGateConsumesOnlyCurrentExactDecision(t *testing.T) {
	now := time.Unix(1000, 0)
	gate, err := New(testVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"messages":[{"seq":1}]}`)
	id := testIdentity()
	challenge, commitment, err := gate.Prepare("mls_decrypt_batch_for_app_display", request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDecision(challenge, commitment, now)
	if err := gate.VerifyAndConsume(decision, "mls_decrypt_batch_for_app_display", request, id); err != nil {
		t.Fatalf("valid current decision refused: %v", err)
	}
	if err := gate.VerifyAndConsume(decision, "mls_decrypt_batch_for_app_display", request, id); err == nil {
		t.Fatal("a consumed challenge was reused")
	}
}

func TestGateRejectsChangedRequestAndLocalSession(t *testing.T) {
	now := time.Unix(1000, 0)
	gate, err := New(testVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	request := []byte(`{"messages":[{"seq":1}]}`)
	challenge, commitment, err := gate.Prepare("mls_decrypt_batch_for_app_display", request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDecision(challenge, commitment, now)
	if gate.VerifyAndConsume(decision, decision.Action, []byte(`{"messages":[{"seq":2}]}`), id) == nil {
		t.Fatal("changed request accepted")
	}
	challenge, commitment, err = gate.Prepare(decision.Action, request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision = testDecision(challenge, commitment, now)
	id.LocalSession = "another-local-session"
	if gate.VerifyAndConsume(decision, decision.Action, request, id) == nil {
		t.Fatal("another local session accepted")
	}
}

func TestGateRejectsExpiredAndUnsignedDecision(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := now
	gate, err := New(testVerifier{}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	request := []byte("sealed")
	challenge, commitment, err := gate.Prepare("mls_decrypt_batch_for_app_display", request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDecision(challenge, commitment, now)
	decision.Signature = "forged"
	if gate.VerifyAndConsume(decision, decision.Action, request, id) == nil {
		t.Fatal("forged decision accepted")
	}
	challenge, commitment, err = gate.Prepare(decision.Action, request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision = testDecision(challenge, commitment, now)
	clock = now.Add(16 * time.Second)
	if gate.VerifyAndConsume(decision, decision.Action, request, id) == nil {
		t.Fatal("expired decision accepted")
	}
}

func TestDecisionCanonicalMatchesAPIWireContract(t *testing.T) {
	d := testDecision("challenge", "commitment", time.Unix(1000, 0))
	want := "dragpass.keeper.online.chat|1|33:mls_decrypt_batch_for_app_display|9:challenge|10:commitment|7:account|6:device|42|7:binding|12:conversation|3:org|1000000|1015000|3"
	if got := d.Canonical(); got != want {
		t.Fatalf("canonical mismatch: %q", got)
	}
}

func TestGateVerifiesPinnedServerSignatureAndSingleWinner(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	store := testdouble.NewMemorySecretStore()
	if err := keychain.SaveServerPublicKeyForVersion(store, 3, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	gate, err := New(verifier.NewDefaultServerKeyVerifier(store), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	request := []byte("sealed")
	challenge, commitment, err := gate.Prepare("mls_decrypt_batch_for_app_display", request, id)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDecision(challenge, commitment, now)
	hash := sha256.Sum256([]byte(decision.Canonical()))
	signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	decision.Signature = base64.StdEncoding.EncodeToString(signature)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- gate.VerifyAndConsume(decision, decision.Action, request, id)
		}()
	}
	wg.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result == nil {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("one signed decision admitted %d concurrent callers", allowed)
	}
}
