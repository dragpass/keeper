// Keep protocol aliases used by the root package and its tests.

package keystore

import "github.com/dragpass/keeper/internal/keystore/proto"

type (
	BaseResponse                        = proto.BaseResponse
	AESUnwrapAndEncryptResponseData     = proto.AESUnwrapAndEncryptResponseData
	ClipboardCopyResponseData           = proto.ClipboardCopyResponseData
	DEKGenerateAndWrapDualResponseData  = proto.DEKGenerateAndWrapDualResponseData
	DEKRewrapForMemberResponseData      = proto.DEKRewrapForMemberResponseData
	DEKRotateToDeviceKeyResponseData    = proto.DEKRotateToDeviceKeyResponseData
	DEKUnwrapAndEncryptResponseData     = proto.DEKUnwrapAndEncryptResponseData
	GetDeviceKeyResponseData            = proto.GetDeviceKeyResponseData
	GetPublicKeyResponseData            = proto.GetPublicKeyResponseData
	GetServerPublicKeyResponseData      = proto.GetServerPublicKeyResponseData
	GroupDEKGenerateAndOpenResponseData = proto.GroupDEKGenerateAndOpenResponseData
	GroupSessionStatusResponseData      = proto.GroupSessionStatusResponseData
	SignAliasResponseData               = proto.SignAliasResponseData
	SignAliasWithTimestampResponseData  = proto.SignAliasWithTimestampResponseData
)
