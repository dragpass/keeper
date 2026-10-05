package localrpc

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// guestTranscryptMaxRequestBytes leaves room for the largest org token a guest
// share can hold: the server keeps at most 256 KiB of guest ciphertext, and the
// org token's ciphertext is the same size before re-encryption.
const guestTranscryptMaxRequestBytes = 512 * 1024

// groupHandleRoutes open a group DEK grant into a handle and use it for the
// Secure Message and the external share, as the Extension background does.
// No route here takes an AAD or returns a key: the message seal builds its
// AAD from structured fields, the display actions build theirs inside the
// handler, and the guest transcrypt returns only the guest ciphertext and the
// one-time guest key.
var groupHandleRoutes = map[string]appRoute{
	"/v1/group-dek/open": {
		action: proto.ActionGroupSessionOpen,
		input:  func() any { return &proto.GroupSessionOpenRequest{} },
	},
	"/v1/message/seal": {
		action: proto.ActionGroupEncryptWithAAD,
		input:  func() any { return &appMessageSeal{} },
		bind:   bindMessageSeal,
	},
	"/v1/message/display-prepare": {
		action:     proto.ActionMessageDisplayPrepare,
		input:      func() any { return &proto.MessageDisplayPrepareRequest{} },
		plainLimit: proto.MessageDisplayMaxRequestBytes,
	},
	"/v1/message/display": {
		action:     proto.ActionGroupDecryptWithAadForAppDisplay,
		input:      func() any { return &proto.GroupDecryptWithAadForAppDisplayRequest{} },
		plainLimit: proto.MessageDisplayMaxRequestBytes,
	},
	"/v1/guest-share/transcrypt": {
		action:     proto.ActionGroupTranscryptForGuest,
		input:      func() any { return &proto.GroupTranscryptForGuestRequest{} },
		bind:       bindGuestTranscrypt,
		plainLimit: guestTranscryptMaxRequestBytes,
	},
}

// bindGuestTranscrypt requires the org the App applied the external-share
// policy for. The App can paste any token, so the route never transcrypts one
// without naming the org its handle must have been opened for.
func bindGuestTranscrypt(_ *Server, input any) (any, error) {
	in := input.(*proto.GroupTranscryptForGuestRequest)
	if !validUUID(in.ExpectedOrgID) || in.ExpectedOrgID == nilUUID {
		return nil, errAppRouteRefused
	}
	return *in, nil
}

// appMessageSeal names the message, never its AAD, so the route cannot seal
// under the credential or room canonical or any other domain.
type appMessageSeal struct {
	GroupHandle    string `json:"group_handle"`
	OrgID          string `json:"org_id"`
	GroupID        string `json:"group_id"`
	DekVersion     int    `json:"dek_version"`
	TokenExpiresAt int64  `json:"token_expires_at"`
	PlaintextB64   string `json:"plaintext_b64"`
}

const (
	messageMaxDekVersion = 2147483647
	messageMaxExpiry     = 99999999999
)

func bindMessageSeal(_ *Server, input any) (any, error) {
	in := input.(*appMessageSeal)
	for _, id := range []string{in.OrgID, in.GroupID} {
		if !validUUID(id) || id == nilUUID {
			return nil, errAppRouteRefused
		}
	}
	if in.DekVersion < 1 || in.DekVersion > messageMaxDekVersion ||
		in.TokenExpiresAt < 1 || in.TokenExpiresAt > messageMaxExpiry {
		return nil, errAppRouteRefused
	}
	plaintext, err := base64.StdEncoding.DecodeString(in.PlaintextB64)
	size := len(plaintext)
	secure.Zeroize(plaintext)
	if err != nil || size < proto.MessagePlaintextMinBytes || size > proto.MessagePlaintextMaxBytes {
		return nil, errAppRouteRefused
	}
	aad := proto.MessageAADCanonical(in.OrgID, in.GroupID, in.DekVersion, proto.MessageSchemaVersion, in.TokenExpiresAt)
	return proto.GroupEncryptWithAADRequest{
		GroupHandle:  in.GroupHandle,
		PlaintextB64: in.PlaintextB64,
		AADB64:       base64.StdEncoding.EncodeToString([]byte(aad)),
	}, nil
}
