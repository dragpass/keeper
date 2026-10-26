// credential_confirmation_test.go — a personal-scope credential request runs
// only with the server's fresh confirmation for its nonce and entry. The
// organization path has its server gate in the Group DEK grant; the personal
// path opens a device-local DEK, so without this nothing the server decides
// after the resolve (a revoked token, a revoked approval) could stop it.

package handlers

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crypto/rand"
	"encoding/base64"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// confirmationRejectingVerifier accepts every server signature except one over
// an execution confirmation: a confirmation the server never signed.
type confirmationRejectingVerifier struct{}

func (confirmationRejectingVerifier) Verify(token, _ string, _ uint) error {
	if strings.HasPrefix(token, "dragpass.credential-execution-confirmation|") {
		return errors.New("server signature verification failed")
	}
	return nil
}

type personalCredentialRig struct {
	deps  Deps
	hits  *atomic.Int32
	req   proto.CredentialHTTPRequest
	nonce string
}

// newPersonalCredentialRig seals a credential under this device's personal DEK
// and prepares an armed request to a TLS test server that counts its hits.
func newPersonalCredentialRig(t *testing.T) personalCredentialRig {
	t.Helper()
	hits := &atomic.Int32{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	prev := testTLSConfigHook
	testTLSConfigHook = func(cfg *tls.Config) {
		cfg.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	prevLoopback := testAllowLoopbackDial
	testAllowLoopbackDial = true
	t.Cleanup(func() { testTLSConfigHook = prev; testAllowLoopbackDial = prevLoopback })

	deps, _, store := newTestDeps(t)
	deviceKey := make([]byte, 32)
	for i := range deviceKey {
		deviceKey[i] = byte(i + 7)
	}
	setKeychainDeviceKey(t, store, deviceKey)
	if dual := signupDEKForTest(deps, "password"); !dual.Success {
		t.Fatalf("generate personal DEK: %s", dual.Error)
	}
	var dek []byte
	if err := withCredentialDEK(deps, credentialKeySource{useLocalPersonalDEK: true}, func(raw []byte) error {
		dek = append([]byte(nil), raw...)
		return nil
	}); err != nil {
		t.Fatalf("personal DEK: %v", err)
	}
	cred := `{"type":"api_token","secret":{"token":"PERSONAL_SECRET_VALUE"}}`
	iv, ct, err := crypto.SealAESGCM(rand.Reader, dek, []byte(cred), []byte(credTestAAD))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	header := map[string]string{"Authorization": "Bearer {{secret.token}}"}
	policy := credTestPolicy([]string{hostOf(t, ts.URL)}, []string{"GET"})
	policy.HeaderTemplate = header
	policy = armCredentialPolicy(t, deps, policy, ts.URL+"/x", nil)
	return personalCredentialRig{
		deps:  deps,
		hits:  hits,
		nonce: policy.ExecutionNonce,
		req: proto.CredentialHTTPRequest{
			UseLocalPersonalDEK: true,
			IVB64:               base64.StdEncoding.EncodeToString(iv),
			CiphertextB64:       base64.StdEncoding.EncodeToString(ct),
			AADB64:              base64.StdEncoding.EncodeToString([]byte(credTestAAD)),
			TargetURL:           ts.URL + "/x",
			Method:              "GET",
			HeaderTemplate:      header,
			Policy:              policy,
		},
	}
}

func (r personalCredentialRig) confirmation() *proto.CredentialExecutionConfirmation {
	return &proto.CredentialExecutionConfirmation{
		ExecutionNonce:   r.req.Policy.ExecutionNonce,
		EntryID:          r.req.Policy.EntryID,
		Expiry:           time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339),
		Signature:        "test-signature",
		ServerKeyVersion: 1,
		SignatureAlg:     credentialPolicySignatureAlg,
	}
}

func TestCredentialHTTPPersonal_RunsWithAFreshServerConfirmation(t *testing.T) {
	rig := newPersonalCredentialRig(t)
	rig.req.ExecutionConfirmation = rig.confirmation()
	resp := HandleCredentialHTTPRequest(rig.deps, rig.req)
	if !resp.Success || rig.hits.Load() != 1 {
		t.Fatalf("confirmed personal request: success=%v code=%s hits=%d", resp.Success, resp.ErrorCode, rig.hits.Load())
	}
}

func TestCredentialHTTPPersonal_RefusesWithoutAValidServerConfirmation(t *testing.T) {
	cases := map[string]func(r personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation{
		"missing": func(personalCredentialRig, *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			return nil
		},
		"another nonce": func(_ personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			c.ExecutionNonce = strings.Repeat("A", proto.CredentialExecutionNonceChars)
			return c
		},
		"another entry": func(_ personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			c.EntryID = "entry_other"
			return c
		},
		"expired": func(_ personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			c.Expiry = time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
			return c
		},
		"too long-lived": func(_ personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			c.Expiry = time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
			return c
		},
		"another algorithm": func(_ personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			c.SignatureAlg = "hmac-sha256"
			return c
		},
		"not signed by the server": func(r personalCredentialRig, c *proto.CredentialExecutionConfirmation) *proto.CredentialExecutionConfirmation {
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newPersonalCredentialRig(t)
			if name == "not signed by the server" {
				rig.deps.ServerKeyVerifier = confirmationRejectingVerifier{}
			}
			rig.req.ExecutionConfirmation = mutate(rig, rig.confirmation())
			resp := HandleCredentialHTTPRequest(rig.deps, rig.req)
			if resp.Success || resp.ErrorCode != "credential_confirmation_invalid" {
				t.Fatalf("success=%v code=%q, want credential_confirmation_invalid", resp.Success, resp.ErrorCode)
			}
			if rig.hits.Load() != 0 {
				t.Fatalf("the target received %d request(s)", rig.hits.Load())
			}
			// Refused before the nonce is spent: nothing ran.
			if !rig.deps.CredentialNonces.Consume(rig.nonce, rig.deps.Now()) {
				t.Fatal("a refused request spent the execution nonce")
			}
		})
	}
}
