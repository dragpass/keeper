// session_errors.go — single helper that maps group/recovery session
// store.Use errors to a BaseResponse. The old `groupSessionUseError` /
// `recoverySessionUseError` helpers were identical except for sentinel error
// types, so they were consolidated into one entry point.
//
// The NotFound / Expired sentinel errors enable automatic Extension-side
// branching (cache invalidation + re-open attempt) via the ErrorCode mapping.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// sessionUseError converts an error returned by group/recovery session
// store.Use into a BaseResponse. ErrCodeNotFound / ErrCodeExpiredSession
// mappings are used by Extension-side auto-retry (re-open) branching. Other
// errors classify as ErrCodeInternal with a context prefix to identify the
// call site.
//
// The session kind (group vs recovery) is auto-branched by the sentinel error
// type — the caller does not specify it.
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
