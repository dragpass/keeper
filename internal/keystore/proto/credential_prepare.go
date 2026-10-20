// credential_prepare.go — the request and response of
// credential_execution_prepare, the first step of a credential use.
//
// The Keeper mints an execution nonce and remembers it in process memory. The
// server signs that nonce into the credential policy, and the sink action that
// presents the policy consumes it. Nothing here is key material.

package proto

const (
	// CredentialPolicyVersion is the only signed policy format Keeper accepts.
	// Version 2 binds the execution nonce, the exact query and the body digest.
	// A policy without it is refused before its signature is checked; there is
	// no fallback to the format that bound neither.
	CredentialPolicyVersion = 2

	// CredentialExecutionNonceChars — 32 CSPRNG bytes as unpadded Base64URL.
	CredentialExecutionNonceBytes = 32
	CredentialExecutionNonceChars = 43
)

// CredentialExecutionPrepareRequest takes no fields. The nonce is not bound to
// an entry or a target here: the server binds it, together with everything
// else it signs, when it answers the resolve.
type CredentialExecutionPrepareRequest struct{}

func (CredentialExecutionPrepareRequest) Validate() error { return nil }

// CredentialExecutionPrepareResponseData carries the minted nonce and the
// moment the Keeper forgets it.
type CredentialExecutionPrepareResponseData struct {
	ExecutionNonce string `json:"execution_nonce"`
	ExpiresAt      string `json:"expires_at"`
}
