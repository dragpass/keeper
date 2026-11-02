// group_dek_rewrap_target.go — which keys a Group DEK may be wrapped to when
// the request names no account.
//
// A wrap that names an account goes through the peer key pin. A wrap that
// names none has no pin to consult, so the only key it may target is one this
// Keeper reads from its own keychain. Accepting any other key there would let
// whoever speaks to the Keeper over Native Messaging receive the Group DEK
// under a key it holds and open bound tokens offline, outside every expiry
// and display decision Keeper enforces.
//
// Contract: docs/protocol.md "Group DEK rewrap targets".

package handlers

import (
	"crypto/rsa"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// isOwnAccountKey reports whether target is this Keeper's active account key
// or the key staged by an account key rotation, which the rotation rewraps
// every grant to before the server accepts it. Keys are compared parsed, so
// PEM line wrapping cannot make the same key look foreign or a foreign key
// look like ours.
func isOwnAccountKey(d Deps, target *rsa.PublicKey) (bool, error) {
	activePEM, err := keychain.GetPublicKey(d.Store)
	if err != nil {
		return false, err
	}
	active, err := crypto.ParsePublicKey(activePEM)
	if err != nil {
		return false, err
	}
	if active.Equal(target) {
		return true, nil
	}
	stagedPEM, err := keychain.GetPendingPublicKey(d.Store)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	staged, err := crypto.ParsePublicKey(stagedPEM)
	if err != nil {
		return false, err
	}
	return staged.Equal(target), nil
}

// requireOwnTargetWithoutAccount refuses an account-less wrap to any key that
// is not this Keeper's own.
func requireOwnTargetWithoutAccount(d Deps, target *rsa.PublicKey, field string) (proto.BaseResponse, bool) {
	own, err := isOwnAccountKey(d, target)
	if err != nil {
		d.Logger.Printf("group dek wrap target error: failed to read own key: %v", err)
		return errs.Response(err), false
	}
	if !own {
		d.Logger.Println("group dek wrap refused: no account named and the target is not this Keeper's key")
		return errs.CodeResponse(errs.ErrCodeValidation,
			field+": a wrap that names no account must target this Keeper's own account key"), false
	}
	return proto.BaseResponse{}, true
}
