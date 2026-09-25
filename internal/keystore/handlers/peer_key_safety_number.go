// peer_key_safety_number.go — the pairwise safety number (0.0.55, design §0.3
// policy 3, Q10 (a)).
//
//	value  = SHA-256("dragpass.safety_number|1|" + a1 + "|" + fp1 + "|" + a2 + "|" + fp2)
//	digits = value as a big-endian integer mod 10^60, zero-padded to 60
//
// (a1, fp1) and (a2, fp2) are the owner and the peer, each with its account
// key fingerprint (hex(sha256(PEM bytes))), sorted by account id so both
// sides compute the same value. The owner's half comes from the key this
// Keeper holds, never from the request. The app shows the digits in 12 groups
// of 5 and a QR code of the value; comparing or scanning either and
// confirming goes through peer_key_pin_verify, which recomputes the value.
//
// It is a comparison aid over the account keys, nothing more: it proves the
// two devices hold the same pair of keys, not who is behind either one.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const safetyNumberDomain = "dragpass.safety_number|1|"

// safetyNumber computes the value and its digits for one pair.
func safetyNumber(ownerID, ownerFP, peerID, peerFP string) ([]byte, string) {
	first, second := [2]string{ownerID, ownerFP}, [2]string{peerID, peerFP}
	if peerID < ownerID {
		first, second = second, first
	}
	sum := sha256.Sum256([]byte(safetyNumberDomain + strings.Join([]string{first[0], first[1], second[0], second[1]}, "|")))
	modulus := new(big.Int).Exp(big.NewInt(10), big.NewInt(proto.SafetyNumberDigits), nil)
	n := new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), modulus)
	return sum[:], fmt.Sprintf("%0*s", proto.SafetyNumberDigits, n.String())
}

// ownSafetyNumber is safetyNumber with the owner's half read from this
// Keeper's own key.
func ownSafetyNumber(d Deps, ownerID, peerID, peerPEM string) (value []byte, digits, ownFP, peerFP string, resp proto.BaseResponse, ok bool) {
	own, err := keychain.GetPublicKey(d.Store)
	if err != nil || own == "" {
		return nil, "", "", "", errs.CodeResponse(errs.ErrCodeNotFound, "account public key not found (signup required first)"), false
	}
	if _, err := crypto.ParsePublicKey(peerPEM); err != nil {
		return nil, "", "", "", errs.CodeResponse(errs.ErrCodeValidation, "failed to parse public key"), false
	}
	ownFP = crypto.AccountKeyFingerprint([]byte(own))
	peerFP = crypto.AccountKeyFingerprint([]byte(peerPEM))
	value, digits = safetyNumber(ownerID, ownFP, peerID, peerFP)
	return value, digits, ownFP, peerFP, proto.BaseResponse{}, true
}

// HandlePeerKeySafetyNumber returns the pair's safety number.
func HandlePeerKeySafetyNumber(d Deps, req proto.PeerKeySafetyNumberRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if resp, ok := requirePeerKeyOwner(d, req.OwnerAccountID); !ok {
		return resp
	}
	value, digits, ownFP, peerFP, resp, ok := ownSafetyNumber(d, req.OwnerAccountID, req.AccountID, req.PublicKey)
	if !ok {
		return resp
	}
	d.Logger.Println("peer key safety number successful")
	return proto.BaseResponse{Success: true, Data: proto.PeerKeySafetyNumberResponseData{
		SafetyNumber:    digits,
		SafetyNumberB64: base64.StdEncoding.EncodeToString(value),
		OwnFingerprint:  ownFP,
		PeerFingerprint: peerFP,
	}}
}
