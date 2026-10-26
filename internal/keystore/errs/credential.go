package errs

const (
	// ErrCodeCredentialNonceInvalid — the signed policy names an execution nonce
	// this Keeper's nonce map does not hold: never minted there (another
	// device, OS user or standalone process), already consumed, or forgotten
	// (expired, or the serving Keeper restarted). Nothing was opened and
	// nothing was sent. The caller needs a new prepare and a new resolve.
	ErrCodeCredentialNonceInvalid ErrorCode = "credential_nonce_invalid"

	// ErrCodeCredentialOutcomeUnknown — the HTTP sink wrote the request headers
	// and then the transport failed. The target may have received and acted on
	// the request. The nonce is spent; the caller must not retry automatically.
	ErrCodeCredentialOutcomeUnknown ErrorCode = "credential_outcome_unknown"

	// ErrCodeCredentialConfirmationInvalid — a personal-scope request carried no
	// server confirmation, or one that is expired, unsigned, or names another
	// nonce or entry. Nothing was opened and nothing was sent; the nonce is
	// left in place.
	ErrCodeCredentialConfirmationInvalid ErrorCode = "credential_confirmation_invalid"
)
