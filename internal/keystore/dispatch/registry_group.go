// Group DEK action registrations.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func groupActions() map[string]action {
	return map[string]action{
		// The App's recovery: the handle it acts on is opened by an App-only
		// recovery action.
		proto.ActionDEKRewrapWithOldKeyToSelf: wrap(handlers.HandleDEKRewrapWithOldKeyToSelf).appOnlyAction(),

		// Group DEK opaque handle
		proto.ActionGroupSessionOpen:  wrap(handlers.HandleGroupSessionOpen).onMCP(),
		proto.ActionGroupSessionClose: wrap(handlers.HandleGroupSessionClose).onMCP(),

		// Admin-path raw-free composite actions (Group DEK never crosses into JS).
		proto.ActionGroupDEKGenerateAndOpen: wrap(handlers.HandleGroupDEKGenerateAndOpen),
		// Capped rather than plain wrap: both take account key trust fields
		// whose size the caller controls, and the ceiling has to apply before
		// the Group DEK is unwrapped.
		proto.ActionDEKRewrapForMember: wrapCapped(
			proto.DEKRewrapMaxRequestBytes, handlers.HandleDEKRewrapForMember,
		),
		proto.ActionDEKUnwrapAndRewrapForMany: wrapCapped(
			proto.DEKRewrapMaxRequestBytes, handlers.HandleDEKUnwrapAndRewrapForMany,
		),

		// decrypt-to-clipboard (Keeper-owned plaintext sink)
		proto.ActionGroupDecryptToClipboard: wrap(handlers.HandleGroupDecryptToClipboard),

		// raw Group DEK direct AES-GCM encrypt (mirror of group_decrypt_to_clipboard).
		proto.ActionGroupEncrypt: wrap(handlers.HandleGroupEncrypt),

		// AAD-binding variant of group_encrypt: binds a canonical context AAD
		// into the GCM tag to prevent ciphertext swap across contexts.
		proto.ActionGroupEncryptWithAAD: wrap(handlers.HandleGroupEncryptWithAAD),

		// Audit-only version actions. Strict decoders, like the message
		// actions: each request is bound into a server signature.
		proto.ActionGroupEncryptAudit:            direct(handlers.HandleGroupEncryptAudit),
		proto.ActionGroupDecryptAuditToClipboard: direct(handlers.HandleGroupDecryptAuditToClipboard),
	}
}
