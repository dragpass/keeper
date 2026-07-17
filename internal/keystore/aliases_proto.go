// Proto envelope + ResponseData aliases — keystore root (main.go) 와 일부
// keystore package 내부 (test 포함) 가 prefix 없이 / keystore.X 로 참조하는
// 것만 보존.

package keystore

import "github.com/dragpass/keeper/internal/keystore/proto"

type (
	BaseResponse                           = proto.BaseResponse
	AESUnwrapAndEncryptResponseData        = proto.AESUnwrapAndEncryptResponseData
	ClipboardCopyResponseData              = proto.ClipboardCopyResponseData
	DEKGenerateAndWrapDualResponseData     = proto.DEKGenerateAndWrapDualResponseData
	DEKGenerateAndWrapPasswordResponseData = proto.DEKGenerateAndWrapPasswordResponseData
	DEKRewrapForMemberResponseData         = proto.DEKRewrapForMemberResponseData
	DEKRotateToDeviceKeyResponseData       = proto.DEKRotateToDeviceKeyResponseData
	DEKUnwrapAndEncryptResponseData        = proto.DEKUnwrapAndEncryptResponseData
	GetDeviceKeyResponseData               = proto.GetDeviceKeyResponseData
	GetPublicKeyResponseData               = proto.GetPublicKeyResponseData
	GetServerPublicKeyResponseData         = proto.GetServerPublicKeyResponseData
	GroupDEKGenerateAndOpenResponseData    = proto.GroupDEKGenerateAndOpenResponseData
	GroupSessionStatusResponseData         = proto.GroupSessionStatusResponseData
	SignAliasResponseData                  = proto.SignAliasResponseData
	SignAliasWithTimestampResponseData     = proto.SignAliasWithTimestampResponseData
	WrapGroupDEKResponseData               = proto.WrapGroupDEKResponseData
)
