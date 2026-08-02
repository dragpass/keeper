// Keep the crypto aliases used by the root package and its tests.

package keystore

import "github.com/dragpass/keeper/internal/keystore/crypto"

var (
	AESGCMDecryptBase64 = crypto.AESGCMDecryptBase64
	EncryptData         = crypto.EncryptData
	GenerateRSAKeyPair  = crypto.GenerateRSAKeyPair
	ParsePublicKey      = crypto.ParsePublicKey
)
