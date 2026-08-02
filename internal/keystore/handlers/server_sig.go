// Server signature failures are normalized at the handler boundary.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func verifyServerSig(d Deps, token, sig string, version uint, context string) (bool, proto.BaseResponse) {
	if err := d.ServerKeyVerifier.Verify(token, sig, version); err != nil {
		d.Logger.Printf("%s server signature verification error: %v", context, err)
		return false, errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	d.Logger.Println(context + " server signature verification successful")
	return true, proto.BaseResponse{}
}
