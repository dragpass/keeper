// aliases.go — backward-compat re-export facade for all keystore subpackages.
//
// Originally a single 580+ line root file. The aliases are split per domain
// into sibling `aliases_<domain>.go` files so any future addition lands next
// to its peers rather than padding this overview.
//
// Sibling files and their domains:
//
//   - aliases_anchor.go    Root pubkey trust anchor
//   - aliases_crypto.go    AES + RSA helpers
//   - aliases_errs.go      Error response envelopes + ErrCode
//   - aliases_keychain.go  SecretStore + sentinel errors
//   - aliases_logger.go    Std/Memory Logger
//   - aliases_proto.go     Request/response envelopes + Validator + Action*
//   - aliases_sessions.go  Group/Recovery SessionStore
//   - aliases_verifier.go  ServerKeyVerifier
//   - aliases_version.go   Binary version metadata
//   - aliases_dispatch.go  HandleRequest + Messenger bindings
//
// Two domains are doc-only — no aliases, just policy notes:
//
// **Handlers:** all handler bodies live in the internal/keystore/handlers/
// subpackage. keystore root keeps only one alias pattern: `keystore.HandleX(req)`-style
// free functions used by main.go's HandleRequest dispatch + dispatcher_test.go's
// JSON envelope scenarios + production-keychain integration tests like
// dek_rewrap_test, refresh_server_keys_test, rotate_*_test. Unit tests call
// handlers.HandleX(deps, req) directly, while production goes through the
// dispatcher's `HandleRequest` JSON envelope.
//
// **Bootstrap:** the body lives in internal/keystore/keychain/bootstrap.go.
// main.go and the facade tests inject App.Store / App.Logger explicitly and
// call keychain.EnsureServerPublicKey directly. Cleanup in tests like
// handlers/refresh_server_keys_test.go targets store slots via config
// constants like `config.Service` + `config.DragPassServerPublicKeyActiveVersion`.
//
// LGPL note: aliases exist because keystore root historically held every
// symbol. keystore root remains as a façade for tests and main.go. New code
// should use the subpackage qualifier directly when possible (proto.X,
// crypto.X, ...).

package keystore
