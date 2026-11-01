// group_encrypt.go — the AAD-free Group drag seal, now refused.
//
// A token sealed with the raw Group DEK and no AAD carries an `E=` expiry
// nobody can authenticate, and no action opens it any more. Sealing one would
// only produce a token nobody can view, so group_encrypt answers
// TOKEN_LEGACY_REFUSED. Drag tokens are sealed by group_encrypt_bound
// (bound_token.go).

package handlers

import "github.com/dragpass/keeper/internal/keystore/proto"

// HandleGroupEncrypt refuses the AAD-free Group drag seal.
func HandleGroupEncrypt(d Deps, _ proto.GroupEncryptRequest) proto.BaseResponse {
	return legacyTokenRefused(d, "group encrypt")
}
