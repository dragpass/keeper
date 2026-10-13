// group_grant.go — Group DEK grant policy: the OAEP label a grant is opened and
// rewrapped under, and the handle policy checks the drag actions share.
//
// Every action that unwraps a Group DEK grant takes an optional grant_context.
// The label it implies is used for the unwrap and, on the rewrap actions, for
// every new wrap, so a grant keeps its policy through invitations, rotations,
// recoveries and archive re-grants. No action takes a separate output label.

package handlers

import (
	"crypto/rsa"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// errHandleAuditOnly is what an AAD-free drag action's session closure returns
// on an audit-only handle; handleSessionError turns it into its error code.
var errHandleAuditOnly = errors.New("group handle is audit-only")

// isAuditOnlyLabel reports whether a handle was opened from an audit-only grant.
func isAuditOnlyLabel(label sessions.Label) bool {
	return label.GrantPolicy == proto.GrantPolicyAuditOnlyV1
}

// handleLabel is what a handle remembers about the grant it was opened from.
func handleLabel(orgID string, gc *proto.GrantContext) sessions.Label {
	if gc == nil {
		return sessions.Label{OrgID: orgID}
	}
	return sessions.Label{
		OrgID:       gc.OrgID,
		GrantPolicy: gc.Policy,
		GroupID:     gc.GroupID,
		DekVersion:  gc.DekVersion,
	}
}

// unwrapGrant opens one wrapped Group DEK under the label gc implies. The
// caller zeroizes the result.
func unwrapGrant(privKey *rsa.PrivateKey, encrypted []byte, gc *proto.GrantContext) ([]byte, error) {
	return crypto.DecryptDataWithLabel(privKey, encrypted, proto.GroupDEKGrantLabel(gc))
}

// wrapGrant wraps a raw Group DEK to pub under the label gc implies.
func wrapGrant(pub *rsa.PublicKey, groupDEK []byte, gc *proto.GrantContext) ([]byte, error) {
	return crypto.EncryptDataWithLabel(pub, groupDEK, proto.GroupDEKGrantLabel(gc))
}

// grantOpenFailure is the answer to a grant that did not open. Under the
// audit-only label it gets its own code: the Extension reports it, since a
// grant wrapped without the label is a rotation nobody can use.
func grantOpenFailure(gc *proto.GrantContext, err error) proto.BaseResponse {
	if gc.IsAuditOnly() {
		return errs.CodeResponse(errs.ErrorCode(proto.GroupGrantPolicyMismatch),
			"the grant did not open under the audit-only policy it was presented with")
	}
	return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt failed: "+err.Error())
}

// handleSessionError is sessionUseError plus the handle policy refusal.
func handleSessionError(err error, context string) proto.BaseResponse {
	if errors.Is(err, errHandleAuditOnly) {
		return errs.CodeResponse(errs.ErrorCode(proto.GroupPolicyAuditOnly),
			"this group handle was opened from an audit-only grant; use the audit action")
	}
	return sessionUseError(err, context)
}
