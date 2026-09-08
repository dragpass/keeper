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
	"fmt"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

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
