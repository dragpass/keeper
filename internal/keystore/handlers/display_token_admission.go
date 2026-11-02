package handlers

import "github.com/dragpass/keeper/internal/keystore/proto"

// admitDisplayToken admits a selected drag token for isolated display. Only a
// bound token (docs/protocol.md "Bound drag tokens") carries an authenticated
// expiry: an empty token_expiry is a legacy token and is refused with
// TOKEN_LEGACY_REFUSED, and an expired one with TOKEN_EXPIRED. Keeper builds
// the token AAD itself from the returned expiry and the scope it trusts.
func admitDisplayToken(d Deps, tokenExpiry, action string) (proto.TokenExpiry, proto.BaseResponse, bool) {
	if tokenExpiry == "" {
		return proto.TokenExpiry{}, legacyTokenRefused(d, action), false
	}
	return boundExpiry(d, tokenExpiry, action)
}
