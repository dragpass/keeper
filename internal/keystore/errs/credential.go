package errs

const (
	// ErrCodeCredentialNonceInvalid — the signed policy names an execution nonce
	// this Keeper process did not mint, minted and already consumed, or minted
	// and forgot (expired, or the process restarted). Nothing was opened and
	// nothing was sent. The caller needs a new prepare and a new resolve.
	ErrCodeCredentialNonceInvalid ErrorCode = "credential_nonce_invalid"

	// ErrCodeCredentialOutcomeUnknown — the HTTP sink wrote the request headers
	// and then the transport failed. The target may have received and acted on
	// the request. The nonce is spent; the caller must not retry automatically.
	ErrCodeCredentialOutcomeUnknown ErrorCode = "credential_outcome_unknown"
)
