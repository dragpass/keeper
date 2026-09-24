// mls_authority.go — the signed statements the Commit authority rules read
// (chatstate/authority.go): the server's member-set attestation on a handshake
// row, and an account's own signed rejoin request.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// errAttestationRefused — a commit attestation that does not verify. Answered
// as CHAT_STATE_NOT_AUTHORIZED, like a permit whose signature fails.
var errAttestationRefused = errors.New("mls commit attestation does not verify")

// commitMembers verifies a handshake row's attestation for commit at epoch
// and returns the member set it signs. Nil in, nil out: a row without one is
// no evidence, which the rules read as such. A signature that does not verify
// is a refusal of the request, not a missing attestation, so a tampered row
// never reads as a legacy one.
func commitMembers(
	d Deps, conversationID string, epoch uint64, commit []byte, a *proto.MLSCommitAttestation,
) (*chatstate.ServerCommitMembers, bool) {
	if a == nil {
		return nil, true
	}
	sum := sha256.Sum256(commit)
	canonical := proto.MLSCommitAttestationCanonical(conversationID, epoch, hex.EncodeToString(sum[:]), *a)
	if err := d.ServerKeyVerifier.Verify(canonical, a.Signature, a.ServerKeyVersion); err != nil {
		return nil, false
	}
	return &chatstate.ServerCommitMembers{AccountIDs: a.MemberAccountIDs}, true
}

// rejoinMembers decodes each rejoin and verifies its signed request against
// the KeyPackage it comes with: the KeyPackage's credential names the account
// and device the request names, its leaf signs with the key the request
// names, the request is signed by the account key that leaf's declaration
// carries, and it is recent enough. That account key is then held to this
// owner's pin, or recorded as its first use, when the Commit's entering leaf
// is verified (§5.3): a request signed by any other key never builds.
func rejoinMembers(d Deps, members []proto.MLSRejoinMember) ([]chatstate.RejoinMember, proto.BaseResponse, bool) {
	out := make([]chatstate.RejoinMember, 0, len(members))
	now := d.Now().Unix()
	refuse := func(reason string) ([]chatstate.RejoinMember, proto.BaseResponse, bool) {
		d.Logger.Printf("mls commit build refused a rejoin: %s", reason)
		return nil, errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeRejoinUnverified),
			"the rejoin request is not the account's own signed request for this key package; nothing was built"), false
	}
	for _, m := range members {
		kp, err := base64.StdEncoding.DecodeString(m.KeyPackageB64)
		if err != nil {
			return nil, chatStateInvalidInput("key_package_b64 must be valid standard Base64"), false
		}
		leaf, err := mls.KeyPackageLeaf(kp)
		if err != nil {
			return nil, chatStateFailure(d, "key package identity", err), false
		}
		account, device, err := mls.ParseCredentialIdentity(leaf.Identity)
		if err != nil || account != m.AccountID || device != m.DeviceID {
			return refuse("the key package names another account or device")
		}
		fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.SignatureKey)
		if err != nil || fingerprint != m.Request.SignatureKeyFingerprint {
			return refuse("the key package's leaf is not the key the request names")
		}
		if m.Request.RequestedAt > now+chatStatePermitClockSkewSeconds ||
			now-m.Request.RequestedAt > proto.MLSRejoinStatementMaxAgeSeconds {
			return refuse("the request is outside its window")
		}
		ext, err := decodeMLSLeafExtension(leaf.Declaration)
		if err != nil {
			return refuse("the key package's leaf carries no readable declaration")
		}
		if err := verifyStatementSignature([]byte(ext.AccountPublicKey), m.Request.Signature,
			proto.MLSRejoinStatementCanonical(m.Request)); err != nil {
			return refuse("the request's signature does not verify under the leaf's account key")
		}
		out = append(out, chatstate.RejoinMember{AccountID: m.AccountID, KeyPackage: kp})
	}
	return out, proto.BaseResponse{}, true
}

// HandleMLSRejoinRequestSign signs this device's request to be re-seated in a
// conversation whose every Welcome it could not use (0.0.55, design Q6). The
// request names this account, the device the active leaf belongs to, that
// leaf's key, and now; the account key signs it. The app posts it to the
// server, which serves it to the members, and the member that re-seats this
// account hands it back to its own Keeper, which verifies it before building.
func HandleMLSRejoinRequestSign(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSRejoinRequestSignRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(c.leaf.PublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeFailed), "mls leaf key fingerprint failed")
	}
	statement := proto.MLSRejoinStatement{
		ConversationID:          c.conv,
		AccountID:               c.permit.AccountID,
		DeviceID:                c.leaf.DeviceID,
		SignatureKeyFingerprint: fingerprint,
		RequestedAt:             d.Now().Unix(),
	}
	accountPriv, err := getPrivateKeySecure(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeNotFound, "account keypair not found (signup required first)")
	}
	defer accountPriv.Destroy()
	if statement.Signature, err = signDataSecure(accountPriv, proto.MLSRejoinStatementCanonical(statement)); err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "rejoin request signing failed")
	}
	d.Logger.Println("mls rejoin request sign successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSRejoinRequestSignResponseData{Request: statement}}
}
