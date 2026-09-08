// credential_open_test.go — the shared prelude's cleanup contract.
//
// openCredentialForSink hands the caller a cleanup func rather than zeroizing on
// its own return, because the decrypted secret has to outlive the prelude: the
// sink is what uses it. That makes "cleanup is armed on every path" the property
// the whole zeroize guarantee rests on. The caller defers it before it even
// knows whether the open succeeded, so a nil cleanup would panic and an unarmed
// one would leave the plaintext payload sitting in the heap — including on the
// one refusal that happens *after* the decrypt (a payload that is not a
// credential).
//
// What a test can observe from outside is the secret map, which cleanup empties,
// and the fact that cleanup is never nil and safe to call twice. The payload
// []byte is prelude-local by design; the single place that wipes it is the same
// cleanup body.

package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func credOpenCommon(t *testing.T, groupRaw []byte, handle, plaintext, aad string) credentialRequestCommon {
	t.Helper()
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, plaintext, aad)
	return credentialRequestCommon{
		keySource:     credentialKeySource{groupHandle: handle},
		ivB64:         ivB64,
		ciphertextB64: ctB64,
		aadB64:        aadB64,
		policy:        credTestPolicy([]string{credRejectHost}, []string{"GET"}),
		action:        "credential open test",
	}
}

func TestOpenCredentialForSink_CleanupIsArmedOnEveryStage(t *testing.T) {
	matchOK := func() (bool, proto.BaseResponse) { return true, proto.BaseResponse{} }
	matchRefuses := func() (bool, proto.BaseResponse) { return false, proto.BaseResponse{} }

	cases := []struct {
		stage   string
		match   func() (bool, proto.BaseResponse)
		mutate  func(*credentialRequestCommon)
		wantOK  bool
		payload string
	}{
		{
			stage:  "sealed material is refused",
			match:  matchOK,
			mutate: func(c *credentialRequestCommon) { c.ivB64 = base64.StdEncoding.EncodeToString(make([]byte, 11)) },
		},
		{
			stage:  "policy is refused",
			match:  matchOK,
			mutate: func(c *credentialRequestCommon) { c.policy.Expiry = "2000-01-01T00:00:00Z" },
		},
		{
			stage: "the sink refuses the request",
			match: matchRefuses,
		},
		{
			stage: "the payload does not open",
			match: matchOK,
			mutate: func(c *credentialRequestCommon) {
				c.aadB64 = base64.StdEncoding.EncodeToString([]byte(credRejectAADOtherScope))
			},
		},
		{
			// The one refusal that happens after the decrypt: the payload is in
			// the heap by now and cleanup is the only thing that wipes it.
			stage:   "the payload is not a credential",
			match:   matchOK,
			payload: "not-json",
		},
		{
			stage:   "the credential opens",
			match:   matchOK,
			payload: credRejectPayload,
			wantOK:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.stage, func(t *testing.T) {
			deps, _, _ := newTestDeps(t)
			handle, groupRaw := openSessionForFreshKey(t, deps)
			payload := tc.payload
			if payload == "" {
				payload = credRejectPayload
			}
			common := credOpenCommon(t, groupRaw, handle, payload, credTestAAD)
			if tc.mutate != nil {
				tc.mutate(&common)
			}

			secret, cleanup, resp, ok := openCredentialForSink(deps, common, tc.match)
			if cleanup == nil {
				t.Fatal("cleanup is nil — the caller defers it before testing ok, so this is a panic")
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (response was %q)", ok, tc.wantOK, resp.Error)
			}
			if !tc.wantOK {
				if secret != nil {
					t.Fatalf("a refusal returned a secret map: %v", secret)
				}
				cleanup()
				cleanup() // the deferred call must be safe after any earlier one
				return
			}

			if secret["token"] != credRejectSecret {
				t.Fatalf("secret was not opened: %v", secret)
			}
			cleanup()
			if secret["token"] != "" {
				t.Fatal("cleanup left the secret in the map the caller still holds")
			}
			cleanup()
		})
	}
}
