// Metadata plaintext is passed directly to the caller-owned sink.

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// decryptMetaFields decrypts non-empty fields and invokes fn before returning.
func decryptMetaFields(
	key []byte,
	metaFields map[string]string,
	fn func(name string, plaintext []byte) error,
) error {
	for name, val := range metaFields {
		if val == "" {
			continue
		}
		iv, ct, splitErr := proto.SplitMetaCipherInline(val)
		if splitErr != nil {
			return errors.New("meta " + name + ": " + splitErr.Error())
		}
		pt, openErr := aesGCMOpen(key, iv, ct)
		if openErr != nil {
			return errors.New("decrypt meta " + name + ": " + openErr.Error())
		}
		if err := fn(name, pt); err != nil {
			return err
		}
	}
	return nil
}
