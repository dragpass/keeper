// registry_credential.go — MCP Credential Control Plane action registrations.
//
// Mirrors proto/actions_credential.go. credential_http_request is the Keeper's
// first network surface and its own security domain (policy enforcement, SSRF
// blocking, TLS, redirect blocking, response redaction), so it keeps its own
// registry fragment rather than riding on the Group DEK catalog.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func credentialActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionCredentialHTTPRequest: wrap(handlers.HandleCredentialHTTPRequest),
	}
}
