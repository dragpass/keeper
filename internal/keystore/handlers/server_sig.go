// server_sig.go — helper for the server-signature verification call pattern.
//
// Consolidates the Server signature verification flow that was repeated in 8+
// handler sites into a single helper.
//
// Old pattern (8 call sites):
//
//	if err := d.ServerKeyVerifier.Verify(token, sig, version); err != nil {
//	    d.Logger.Printf("<context> error: %v", err)
//	    return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
//	}
//	d.Logger.Println("server signature verification successful")
//
// New pattern:
//
//	if ok, resp := verifyServerSig(d, token, sig, version, "<context>"); !ok {
//	    return resp
//	}
//
// No change to the external (Verify) call signature — pure helper addition.
// It does not bypass the ServerKeyVerifier interface, so the unit-test
// `AlwaysFailVerifier` injection pattern remains valid.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// verifyServerSig bundles ServerKeyVerifier.Verify call + failure logger
// record + CryptoFailure response creation + success logger record into one
// place.
//
// @return ok=true → verification passed (caller proceeds). ok=false → resp is
//
//	usable as the response envelope directly (caller uses `return resp`).
//
// context is the logger-message prefix (the action name). Do not echo the
// input token / signature values (sentinel regression-guard alignment).
func verifyServerSig(d Deps, token, sig string, version uint, context string) (bool, proto.BaseResponse) {
	if err := d.ServerKeyVerifier.Verify(token, sig, version); err != nil {
		d.Logger.Printf("%s server signature verification error: %v", context, err)
		return false, errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	d.Logger.Println(context + " server signature verification successful")
	return true, proto.BaseResponse{}
}
