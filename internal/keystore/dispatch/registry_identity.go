// registry_identity.go — account identity action registrations.
//
// Mirrors proto/actions_identity.go: device/session state, alias & challenge
// signing, user keypair and device-key rotation, recovery, personal (password)
// DEK operations, and per-device request-signing keys.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func identityActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionGenerateKeypair: wrap(handlers.HandleGenerateKeypair),

		proto.ActionGetDeviceKey:    wrap(handlers.HandleGetDeviceKey),
		proto.ActionSaveDeviceKey:   wrap(handlers.HandleSaveDeviceKey),
		proto.ActionDeleteDeviceKey: wrap(handlers.HandleDeleteDeviceKey),

		// local self-recovery: wipe this device's account-scoped key material
		proto.ActionResetDeviceIdentity: wrap(handlers.HandleResetDeviceIdentity),

		proto.ActionSaveSessionCode: wrap(handlers.HandleSaveSessionCode),
		proto.ActionGetSessionCode:  wrap(handlers.HandleGetSessionCode),

		proto.ActionGetPublicKey: wrap(handlers.HandleGetPublicKey),

		// voluntary user RSA keypair rotation (two-step)
		proto.ActionRotateUserKeypairPrepare: wrap(handlers.HandleRotateUserKeypairPrepare),
		proto.ActionRotateUserKeypairPromote: wrap(handlers.HandleRotateUserKeypairPromote),

		// user keypair rotation partial-failure recovery (status/abort)
		proto.ActionRotateUserKeypairStatus: wrap(handlers.HandleRotateUserKeypairStatus),
		proto.ActionRotateUserKeypairAbort:  wrap(handlers.HandleRotateUserKeypairAbort),

		// voluntary DeviceKey rotation (single composite action)
		proto.ActionRotateDeviceKey: wrap(handlers.HandleRotateDeviceKey),

		proto.ActionSignAlias:              wrap(handlers.HandleSignAlias),
		proto.ActionSignAliasWithTimestamp: wrap(handlers.HandleSignAliasWithTimestamp),
		proto.ActionSignChallengeToken:     wrap(handlers.HandleSignChallengeToken),

		proto.ActionRecoverySign:                    wrap(handlers.HandleRecoverySign),
		proto.ActionGenerateKeypairWithRecoveryWrap: wrap(handlers.HandleGenerateKeypairWithRecoveryWrap),
		// Re-wrap the active privkey when a new RK24 is issued (the keypair
		// itself is unchanged).
		proto.ActionWrapActivePrivateKey: wrap(handlers.HandleWrapActivePrivateKey),

		proto.ActionRecoverySessionOpen:  wrap(handlers.HandleRecoverySessionOpen),
		proto.ActionRecoverySessionClose: wrap(handlers.HandleRecoverySessionClose),

		// personal (password-wrapped) DEK operations
		proto.ActionDEKGenerateAndWrapPassword: wrap(handlers.HandleDEKGenerateAndWrapPassword),
		proto.ActionDEKGenerateAndWrapDual:     wrap(handlers.HandleDEKGenerateAndWrapDual),
		proto.ActionDEKRotateToDeviceKey:       wrap(handlers.HandleDEKRotateToDeviceKey),
		proto.ActionDEKRotateToDeviceKeyPrompt: wrap(handlers.HandleDEKRotateToDeviceKeyPrompt),
		// Re-wrap DEK under a new password (deviceMaster / DEK itself unchanged).
		proto.ActionDEKRotateToNewPassword:  wrap(handlers.HandleDEKRotateToNewPassword),
		proto.ActionDEKUnwrapAndEncrypt:     wrap(handlers.HandleDEKUnwrapAndEncrypt),
		proto.ActionDEKUnwrapAndDecryptMeta: wrap(handlers.HandleDEKUnwrapAndDecryptMeta),
		// decrypt-to-clipboard (Keeper-owned plaintext sink)
		proto.ActionDEKUnwrapAndDecryptToClipboard: wrap(handlers.HandleDEKUnwrapAndDecryptToClipboard),

		// per-device request-signing key actions
		proto.ActionRequestKeyGenerate: wrap(handlers.HandleRequestKeyGenerate),
		proto.ActionRequestKeyStatus:   wrap(handlers.HandleRequestKeyStatus),
		proto.ActionSignRequest:        wrap(handlers.HandleSignRequest),
		// request-signing key rotation
		proto.ActionRotateRequestKeyPrepare: wrap(handlers.HandleRotateRequestKeyPrepare),
		proto.ActionRotateRequestKeyPromote: wrap(handlers.HandleRotateRequestKeyPromote),
		proto.ActionRotateRequestKeyAbort:   wrap(handlers.HandleRotateRequestKeyAbort),
	}
}
