// registry_message.go — Secure Message Overlay display action registrations.
//
// Mirrors proto/actions_message.go. These two are their own security domain —
// a server-signed display permit bound to a Keeper-minted challenge, and the
// protocol's only plaintext-returning response — so they keep their own
// registry fragment rather than riding on the Group DEK catalog.
//
// Unlike every other fragment they register the handler directly instead of
// through wrap(). wrap() routes through `process`, which decodes with plain
// json.Unmarshal; these requests are bound into a server signature, so they
// need a decoder that refuses duplicate keys, unknown fields, and missing
// fields, and they own that decode themselves. See
// handlers/strict_json.go and handlers/message_display.go.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func messageActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionMessageDisplayPrepare:            handlers.HandleMessageDisplayPrepare,
		proto.ActionGroupDecryptWithAadForAppDisplay: handlers.HandleGroupDecryptWithAadForAppDisplay,
	}
}
