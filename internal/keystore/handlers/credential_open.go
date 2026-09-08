// credential_open.go — the part of a credential sink that is not the sink.
//
// Both decrypt-to-tool actions (credential_http_request, credential_exec_request)
// carry the same sealed payload under the same three key sources and open it the
// same way. What differs is only where the decrypted secret goes: one HTTPS
// request, or one child process's environment.
//
// So the opening lives here, once, and the two handler files hold their sink and
// nothing else. Two copies of a security prelude are two things to keep in step,
// and one of them always falls behind.

package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// credentialRequestCommon is the half of a credential request that has nothing
// to do with the sink: which key opens the payload, the sealed material itself,
// and the server-signed policy. Both request types project onto it.
type credentialRequestCommon struct {
	keySource     credentialKeySource
	ivB64         string
	ciphertextB64 string
	aadB64        string
	policy        proto.CredentialPolicy
	// action names the request in a session error message ("credential http
	// request"). It is the only string in the prelude that differs by sink.
	action string
}

// openCredentialForSink runs everything both credential sinks do before the
// secret goes anywhere, in the order they do it:
//
//	sealed material decoded → policy verified (algorithm, expiry, AAD binding,
//	server signature) → the request checked against that verified policy →
//	payload opened under the DEK, AAD-bound → parsed as a credential.
//
// It returns the decrypted secret map the {{secret.<key>}} placeholders resolve
// against. The order is a contract (credential_rejection_test.go pins the
// error_code and message of every stage), which is the reason it lives once
// rather than twice.
//
// matchPolicy is the sink's own half of that checking — the HTTP target and
// templates, or the exec command and cwd. It runs where it does deliberately:
// after the signature is verified, so a mismatch is never reported against a
// policy nobody has checked, and before the payload is opened, so a request that
// is not the approved one never reaches the plaintext.
//
// cleanup is never nil and the caller must `defer cleanup()` immediately, before
// testing ok: it is what zeroizes the decrypted payload, and it is already armed
// on the one failure path that happens after the decrypt.
func openCredentialForSink(d Deps, common credentialRequestCommon,
	matchPolicy func() (bool, proto.BaseResponse),
) (secret map[string]string, cleanup func(), resp proto.BaseResponse, ok bool) {
	cleanup = func() {}

	iv, resp, ok := decodeBase64Len(common.ivB64, 12, "iv_b64")
	if !ok {
		return nil, cleanup, resp, false
	}
	ciphertext, resp, ok := decodeBase64(common.ciphertextB64, "ciphertext_b64")
	if !ok {
		return nil, cleanup, resp, false
	}
	aad, resp, ok := decodeBase64(common.aadB64, "aad_b64")
	if !ok {
		return nil, cleanup, resp, false
	}
	if verified, failure := verifyCredentialPolicy(d, aad, common.policy); !verified {
		return nil, cleanup, failure, false
	}
	// The signed policy is trusted only after verification above.
	if matched, failure := matchPolicy(); !matched {
		return nil, cleanup, failure, false
	}

	// Decrypt inside the session lock, keep the plaintext in a local slice, and
	// hand the caller the zeroizer for it. AAD mismatch (a swapped sealed
	// payload) fails the open here.
	var payload []byte
	var decErr error
	useErr := withCredentialDEK(d, common.keySource, func(dek []byte) error {
		pt, err := AESGCMOpenWithAAD(dek, iv, ciphertext, aad)
		if err != nil {
			decErr = err
			return nil
		}
		payload = pt
		return nil
	})
	if useErr != nil {
		return nil, cleanup, sessionUseError(useErr, common.action), false
	}
	if decErr != nil {
		// Generic message — never echo the decrypt error detail.
		return nil, cleanup, errs.CodeResponse(errs.ErrCodeCryptoFailure, "sealed payload decrypt failed"), false
	}

	// Armed before the parse, so the payload is zeroized even when it turns out
	// not to be a credential.
	var cred sealedCredential
	cleanup = func() {
		secure.Zeroize(payload)
		wipeSecretStrings(cred.Secret)
	}

	if err := json.Unmarshal(payload, &cred); err != nil {
		return nil, cleanup, errs.CodeResponse(errs.ErrCodeCryptoFailure, "sealed payload is not a valid credential"), false
	}
	return cred.Secret, cleanup, proto.BaseResponse{}, true
}

// sealedCredential is the decrypted payload shape. Only the fields the Keeper
// needs to assemble headers are modeled; everything else in the payload JSON is
// ignored. secret is the {key: value} map the {{secret.<key>}} placeholders
// resolve against.
type sealedCredential struct {
	Type   string            `json:"type"`
	Secret map[string]string `json:"secret"`
}

// wipeSecretStrings drops references to secret-bearing map values. Go strings
// are immutable so this cannot overwrite the backing bytes; it removes the last
// reference so the value is eligible for GC. The truly zeroized secret is the
// decrypted payload []byte in the handler.
func wipeSecretStrings(m map[string]string) {
	for k := range m {
		m[k] = ""
	}
}

// credentialKeySource names which key opens a sealed credential payload. Both
// credential sinks (http and exec) carry the same three alternatives on the
// wire, so the branch that picks between them lives once, below.
type credentialKeySource struct {
	groupHandle         string
	encryptedDEKB64     string
	useLocalPersonalDEK bool
}

// withCredentialDEK yields the DEK that opens the sealed payload, dispatching
// on which key source the request carries. Validate() has already enforced
// exactly one.
//
// Both scopes run the *same* decrypt-to-tool body — every one of the eight
// safeguards lives once, above. Duplicating this handler per scope is how two
// copies of a security sink drift apart, so only the key source is branched.
//
//   - org      : raw Group DEK inside the GroupSessionStore memguard lock.
//   - personal : device-wrapped personal DEK unwrapped here and zeroized on
//     return. The device key is fetched from the Keeper Keychain, never IPC.
func withCredentialDEK(d Deps, src credentialKeySource, fn func(dek []byte) error) error {
	if src.groupHandle != "" {
		return d.GroupSessions.Use(src.groupHandle, fn)
	}

	encryptedDEK := src.encryptedDEKB64
	if src.useLocalPersonalDEK {
		var err error
		encryptedDEK, err = keychain.GetPersonalDeviceWrappedDEK(d.Store)
		if err != nil || encryptedDEK == "" {
			return fmt.Errorf("personal DEK not found in keychain")
		}
	}

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return err
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), encryptedDEK)
	if err != nil {
		return err
	}
	defer secure.Zeroize(dek)

	return fn(dek)
}
