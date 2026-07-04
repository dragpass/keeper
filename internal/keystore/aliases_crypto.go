// Crypto helper aliases — keystore package 내부 (test 포함) 에서 bare name 으로
// 참조하는 helper 만 보존. 그 외 (KeyPair, AESGCMEncryptBase64, ParsePrivateKey,
// VerifySignature, SignData, DecryptData) 는 caller 가 없어 제거.

package keystore

import "github.com/dragpass/keeper/internal/keystore/crypto"

var (
	AESGCMDecryptBase64 = crypto.AESGCMDecryptBase64
	EncryptData         = crypto.EncryptData
	GenerateRSAKeyPair  = crypto.GenerateRSAKeyPair
	ParsePublicKey      = crypto.ParsePublicKey
)
