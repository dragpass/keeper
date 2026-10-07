// app_session_refresh_signature.go — the request key's signature over the
// App's cookie session refresh (dp-app-refresh-v1).
//
// The App's refresh token lives in an HttpOnly cookie the App cannot read, so
// the refresh cannot be signed as dp-req-v1 (which binds the token id).
// dp-app-refresh-v1 binds the cookie session through its CSRF binding
// instead. It is its own domain: its first field differs from dp-req-v1, and
// sign_request refuses every canonical that is not dp-req-v1.

package handlers

import (
	"strings"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	appSessionRefreshVersion = "dp-app-refresh-v1"
	appSessionRefreshMethod  = "POST"
	appSessionRefreshPath    = "/api/v1/auth/app-session"
)

// AppSessionRefreshCanonical joins a validated request into the canonical
// ariadne verifies on POST /api/v1/auth/app-session: version, method, path,
// origin, timestamp, nonce, body hash, app binding, device id, one per line
// with no trailing newline.
func AppSessionRefreshCanonical(req proto.SignAppSessionRefreshRequest) string {
	return strings.Join([]string{
		appSessionRefreshVersion,
		appSessionRefreshMethod,
		appSessionRefreshPath,
		req.Origin,
		req.Timestamp,
		req.Nonce,
		req.BodySHA256,
		req.AppBinding,
		req.DeviceID,
	}, "\n")
}

// HandleSignAppSessionRefresh signs the App's session refresh with the active
// request key. Like sign_request, once this Keeper owns a device id it signs
// only for that id.
func HandleSignAppSessionRefresh(d Deps, req proto.SignAppSessionRefreshRequest) proto.BaseResponse {
	d.Logger.Println("sign app session refresh processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if resp, ok := checkStoredDeviceID(d, req.DeviceID, "device_id"); !ok {
		return resp
	}
	return signRequestCanonical(d, AppSessionRefreshCanonical(req))
}
