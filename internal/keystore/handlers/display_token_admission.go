package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// DisplayTokenAdmission decides whether a selected drag token may enter the
// isolated display path. AdmitTokenContext authenticates the token metadata
// that the AES-GCM open will bind as AAD; AdmitAuditToken decides whether an
// audit-only token may be displayed at all.
type DisplayTokenAdmission interface {
	AdmitTokenContext(scope string, aad []byte) (proto.DisplayTokenContext, error)
	AdmitAuditToken() error
}

var errDisplayTokenUnadmitted = errors.New("display token has no authenticated expiry")

func displayTokenRefused() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(proto.DisplayTokenLegacyRefused), "display token expiry cannot be verified")
}

// admitDisplayTokenContext returns the AAD bytes and authenticated context of
// a personal or Group display token, refusing an unknown format, a scope
// mismatch and an expired token at the moment of use.
func admitDisplayTokenContext(d Deps, scope, aadB64 string) ([]byte, proto.DisplayTokenContext, error) {
	if d.DisplayTokens == nil || aadB64 == "" {
		return nil, proto.DisplayTokenContext{}, errDisplayTokenUnadmitted
	}
	aad, err := base64.StdEncoding.DecodeString(aadB64)
	if err != nil || len(aad) == 0 {
		return nil, proto.DisplayTokenContext{}, errDisplayTokenUnadmitted
	}
	ctx, err := d.DisplayTokens.AdmitTokenContext(scope, aad)
	if err != nil || ctx.Scope != scope || ctx.DekVersion <= 0 || ctx.ExpiresAt < 0 ||
		tokenExpiredAt(ctx, d.Now().Unix()) {
		return nil, proto.DisplayTokenContext{}, errDisplayTokenUnadmitted
	}
	return aad, ctx, nil
}

// tokenExpiredAt reports whether an admitted token's authenticated expiry has
// passed. Execute paths re-check it immediately before opening and before
// releasing the envelope, because cryptographic work can outlive the entry check.
func tokenExpiredAt(ctx proto.DisplayTokenContext, now int64) bool {
	return ctx.ExpiresAt != 0 && now >= ctx.ExpiresAt
}

func admitAuditDisplayToken(d Deps) bool {
	return d.DisplayTokens != nil && d.DisplayTokens.AdmitAuditToken() == nil
}
