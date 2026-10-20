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

func identityActions() map[string]action {
	return map[string]action{
		// Account entry is the App's: signup, recovery, RK24 reissue and the
		// sign-in with a key one of them staged run only over the App's local
		// RPC session. The Extension signs in with an active account key only.
		proto.ActionAuthSignupPrepare:          wrap(handlers.HandleAuthSignupPrepare).appOnlyAction(),
		proto.ActionAuthRecoveryReissuePrepare: wrap(handlers.HandleAuthRecoveryReissuePrepare).appOnlyAction(),
		proto.ActionAuthRecoveryBegin:          wrap(handlers.HandleAuthRecoveryBegin).appOnlyAction(),
		proto.ActionAuthRecoveryPrepare:        wrap(handlers.HandleAuthRecoveryPrepare).appOnlyAction(),
		proto.ActionAuthRecoveryAbort:          wrap(handlers.HandleAuthRecoveryAbort).appOnlyAction(),
		proto.ActionAuthSignupAbort:            wrap(handlers.HandleAuthSignupAbort).appOnlyAction(),
		proto.ActionOrgEmergencySeedDerive:     wrap(handlers.HandleOrgEmergencySeedDerive).appOnlyAction(),

		proto.ActionAuthLoginPendingSignAlias:     wrap(handlers.HandleAuthLoginPendingSignAlias).appOnlyAction(),
		proto.ActionAuthLoginPendingSignChallenge: wrap(handlers.HandleAuthLoginPendingSignChallenge).appOnlyAction(),

		proto.ActionGenerateKeypair: wrap(handlers.HandleGenerateKeypair),

		proto.ActionDeleteDeviceKey: wrap(handlers.HandleDeleteDeviceKey),
		proto.ActionDeviceKeyStatus: wrap(handlers.HandleDeviceKeyStatus),
		proto.ActionDeviceKeyEnsure: wrap(handlers.HandleDeviceKeyEnsure),

		// local self-recovery: wipe this device's account-scoped key material
		proto.ActionResetDeviceIdentity: wrap(handlers.HandleResetDeviceIdentity).revoking(ChatRuntimeRevokedReset),

		// one device id per machine and the account binding hint (0.0.58)
		proto.ActionDeviceIDEnsure:        wrap(handlers.HandleDeviceIDEnsure),
		proto.ActionAccountBindingSet:     wrap(handlers.HandleAccountBindingSet).appOnlyAction(),
		proto.ActionDeviceAccountStatus:   wrap(handlers.HandleDeviceAccountStatus),
		proto.ActionDeviceSignout:         wrap(handlers.HandleDeviceSignout),
		proto.ActionAccountBindingSignout: wrap(handlers.HandleAccountBindingSignout).appOnlyAction(),

		proto.ActionSaveSessionCode: wrap(handlers.HandleSaveSessionCode).appOnlyAction(),

		proto.ActionGetPublicKey: wrap(handlers.HandleGetPublicKey),

		// voluntary user RSA keypair rotation (two-step), run from the App's
		// settings. Status and abort stay on Native Messaging: they change no
		// key, and the Keeper-boundary browser E2E drives them there.
		proto.ActionRotateUserKeypairPrepare: wrap(handlers.HandleRotateUserKeypairPrepare).appOnlyAction(),
		proto.ActionRotateUserKeypairPromote: wrap(handlers.HandleRotateUserKeypairPromote).appOnlyAction(),

		// user keypair rotation partial-failure recovery (status/abort)
		proto.ActionRotateUserKeypairStatus: wrap(handlers.HandleRotateUserKeypairStatus),
		proto.ActionRotateUserKeypairAbort:  wrap(handlers.HandleRotateUserKeypairAbort),

		// voluntary DeviceKey rotation (single composite action)
		proto.ActionRotateDeviceKey: wrap(handlers.HandleRotateDeviceKey),

		proto.ActionSignAlias:              wrap(handlers.HandleSignAlias),
		proto.ActionSignAliasWithTimestamp: wrap(handlers.HandleSignAliasWithTimestamp),
		proto.ActionSignChallengeToken:     wrap(handlers.HandleSignChallengeToken),

		proto.ActionRecoverySign: wrap(handlers.HandleRecoverySign),

		proto.ActionRecoverySessionOpen:  wrap(handlers.HandleRecoverySessionOpen),
		proto.ActionRecoverySessionClose: wrap(handlers.HandleRecoverySessionClose).appOnlyAction(),

		// personal (password-wrapped) DEK operations
		proto.ActionDEKRotateToDeviceKey: wrap(handlers.HandleDEKRotateToDeviceKey).appOnlyAction(),
		// Re-wrap DEK under a new password (deviceMaster / DEK itself unchanged).
		proto.ActionDEKRotateToNewPassword:     wrap(handlers.HandleDEKRotateToNewPassword).appOnlyAction(),
		proto.ActionDEKUnwrapAndEncrypt:        wrap(handlers.HandleDEKUnwrapAndEncrypt),
		proto.ActionDEKUnwrapAndEncryptWithAAD: wrap(handlers.HandleDEKUnwrapAndEncryptWithAAD),
		// decrypt-to-clipboard (Keeper-owned plaintext sink)
		proto.ActionDEKUnwrapAndDecryptToClipboard: wrap(handlers.HandleDEKUnwrapAndDecryptToClipboard),
		// the Extension's old device master copy into the empty slot (0.0.58)
		proto.ActionPersonalDEKAdopt: wrap(handlers.HandlePersonalDEKAdopt),

		// per-device request-signing key actions
		proto.ActionRequestKeyGenerate: wrap(handlers.HandleRequestKeyGenerate),
		proto.ActionRequestKeyStatus:   wrap(handlers.HandleRequestKeyStatus),
		proto.ActionSignRequest:        wrap(handlers.HandleSignRequest),
		// the App's cookie session refresh (dp-app-refresh-v1). App-only: the
		// Local RPC route names the paired session's origin, while a Native
		// Messaging frame would name any origin it liked.
		proto.ActionSignAppSessionRefresh: wrap(handlers.HandleSignAppSessionRefresh).appOnlyAction(),
		// request-signing key rotation
		proto.ActionRotateRequestKeyPrepare: wrap(handlers.HandleRotateRequestKeyPrepare),
		proto.ActionRotateRequestKeyPromote: wrap(handlers.HandleRotateRequestKeyPromote),
		proto.ActionRotateRequestKeyAbort:   wrap(handlers.HandleRotateRequestKeyAbort),

		// MLS leaf signature key + its declaration under the account key
		proto.ActionMLSLeafDeclare: wrap(handlers.HandleMLSLeafDeclare).gated(),
		proto.ActionMLSLeafPromote: wrap(handlers.HandleMLSLeafPromote).gated(),
		proto.ActionMLSLeafAbort:   wrap(handlers.HandleMLSLeafAbort).gated(),
		proto.ActionMLSLeafStatus:  wrap(handlers.HandleMLSLeafStatus).chatFree().appOnlyAction(),
		// the old device's approval of a takeover (design Q1)
		proto.ActionMLSLeafHandoverSign: wrap(handlers.HandleMLSLeafHandoverSign).chatFree().appOnlyAction(),

		// KeyPackages for the active leaf, gated by the purpose-bound
		// KeyPackage challenge; their private keys go to the sealed pool.
		proto.MLSKeyPackageGenerate: wrap(handlers.HandleMLSKeyPackageGenerate).gated(),
	}
}
