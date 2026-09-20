// Group DEK action registrations.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func groupActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionDEKRewrapWithOldKey: wrap(handlers.HandleDEKRewrapWithOldKey),

		// Group DEK opaque handle
		proto.ActionGroupSessionOpen:   wrap(handlers.HandleGroupSessionOpen),
		proto.ActionGroupSessionClose:  wrap(handlers.HandleGroupSessionClose),
		proto.ActionGroupSessionStatus: wrap(handlers.HandleGroupSessionStatus),

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

		// raw Group DEK direct batch metadata encrypt/decrypt.
		proto.ActionGroupEncryptMeta: wrap(handlers.HandleGroupEncryptMeta),
		proto.ActionGroupDecryptMeta: wrap(handlers.HandleGroupDecryptMeta),

		// org token → external guest share re-encryption (Keeper-owned re-encrypt
		// sink; plaintext / Group DEK never enter the JS heap).
		proto.ActionGroupTranscryptForGuest: wrap(handlers.HandleGroupTranscryptForGuest),
	}
}
