// credential_confirmation.go — the server's word, immediately before a
// personal-scope execution, that the request may still run.
//
// An organization credential opens under a Group DEK the server grants on
// every use, so a revoked token or member is refused at that grant. A personal
// credential opens under this device's own DEK and needs nothing more from the
// server after the resolve. Without a second gate, a signed policy stayed usable
// for its whole lifetime after the token that obtained it was revoked. The
// confirmation is that gate: the caller asks the server for it after the
// resolve, the server answers only while the token and the approval behind the
// policy are still good, and Keeper refuses a personal request without one.
//
// The signed policy stays required and unchanged. The confirmation adds to it;
// nothing about it can stand in for the policy, and a cached policy cannot
// stand in for a fresh confirmation.

package handlers

import (
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const credentialConfirmationCanonicalPrefix = "dragpass.credential-execution-confirmation|1|"

// credentialConfirmationMaxLifetime bounds how far ahead a confirmation may
// expire. The server issues them for seconds; a longer one is not fresh.
const credentialConfirmationMaxLifetime = 2 * time.Minute

func canonicalExecutionConfirmation(c proto.CredentialExecutionConfirmation) string {
	return credentialConfirmationCanonicalPrefix +
		canonicalCredentialLengthPrefixed(c.ExecutionNonce) + "|" +
		canonicalCredentialLengthPrefixed(c.EntryID) + "|" +
		c.Expiry
}

// verifyExecutionConfirmation checks that c is a current server confirmation
// for exactly this policy's nonce and entry. The policy has been verified.
func verifyExecutionConfirmation(d Deps, p proto.CredentialPolicy, c *proto.CredentialExecutionConfirmation) (bool, proto.BaseResponse) {
	refuse := func(message string) (bool, proto.BaseResponse) {
		return false, errs.CodeResponse(errs.ErrCodeCredentialConfirmationInvalid, message)
	}
	if c == nil {
		return refuse("a personal credential request needs the server's execution confirmation")
	}
	if c.SignatureAlg != credentialPolicySignatureAlg {
		return refuse("unsupported execution confirmation signature algorithm")
	}
	if c.ExecutionNonce != p.ExecutionNonce || c.EntryID != p.EntryID {
		return refuse("the execution confirmation names another request")
	}
	expires, err := time.Parse(time.RFC3339, c.Expiry)
	if err != nil {
		return refuse("execution confirmation expiry is invalid")
	}
	now := d.Now().UTC()
	if !expires.After(now) {
		return refuse("the execution confirmation has expired")
	}
	if expires.After(now.Add(credentialConfirmationMaxLifetime)) {
		return refuse("the execution confirmation lives too long")
	}
	if err := d.ServerKeyVerifier.Verify(canonicalExecutionConfirmation(*c), c.Signature, c.ServerKeyVersion); err != nil {
		d.Logger.Printf("execution confirmation server signature verification error: %v", err)
		return refuse("the execution confirmation is not signed by the server")
	}
	return true, proto.BaseResponse{}
}
