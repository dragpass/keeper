// Session errors preserve retry-relevant protocol codes.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

func sessionUseError(err error, context string) proto.BaseResponse {
	switch err {
	case sessions.ErrGroupSessionNotFound, sessions.ErrRecoverySessionNotFound, sessions.ErrRecoveryKeySessionNotFound:
		return errs.CodeResponse(
			errs.ErrCodeNotFound,
			sessionNotFoundMessage(err),
		)
	case sessions.ErrGroupSessionExpired, sessions.ErrRecoverySessionExpired, sessions.ErrRecoveryKeySessionExpired:
		return errs.CodeResponse(
			errs.ErrCodeExpiredSession,
			sessionExpiredMessage(err),
		)
	default:
		return errs.CodeResponse(errs.ErrCodeInternal, context+": "+err.Error())
	}
}

func sessionNotFoundMessage(err error) string {
	if err == sessions.ErrRecoveryKeySessionNotFound {
		return "recovery key session not found (restart required)"
	}
	if err == sessions.ErrRecoverySessionNotFound {
		return "recovery session not found (re-open required)"
	}
	return "group session not found (re-open required)"
}

func sessionExpiredMessage(err error) string {
	if err == sessions.ErrRecoveryKeySessionExpired {
		return "recovery key session expired (restart required)"
	}
	if err == sessions.ErrRecoverySessionExpired {
		return "recovery session expired (re-open required)"
	}
	return "group session expired (re-open required)"
}
