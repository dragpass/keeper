// registry_credential.go — MCP Credential Control Plane action registrations.
//
// Mirrors proto/actions_credential.go. credential_http_request is the Keeper's
// first network surface and credential_exec_request its first process-spawning
// one; both are their own security domain (policy enforcement, SSRF blocking,
// TLS, redirect blocking, no-shell spawn, clean environment, process-group
// timeout, output redaction), so they keep their own registry fragment rather
// than riding on the Group DEK catalog.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func credentialActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionCredentialHTTPRequest: wrap(handlers.HandleCredentialHTTPRequest),
		proto.ActionCredentialExecRequest: wrap(handlers.HandleCredentialExecRequest),
	}
}
