// Errs aliases — keystore package 내부 test 가 bare name 으로 참조하는 const 만
// 보존. 다른 ErrCodeX / CodeForError / ErrorCode 는 caller 가 없다.

package keystore

import "github.com/dragpass/keeper/internal/keystore/errs"

const (
	ErrCodeUnsupported = errs.ErrCodeUnsupported
)
