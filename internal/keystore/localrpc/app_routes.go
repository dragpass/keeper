package localrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// appRoute is one fixed App action for recovery and group DEK wrapping. The
// request shape is strict and route-specific: fields that would widen the
// underlying action (a caller-chosen wrap target, the unenforced pre-pin
// recipient list) do not exist here, so the App reaches only the enforced form.
type appRoute struct {
	action string
	input  func() any
	// bind turns the decoded input into the action payload. It runs after
	// the strict decode and may consult this Keeper's own state.
	bind func(s *Server, input any) (any, error)
	// plainLimit caps the opened request. Zero means maxRequestBytes.
	plainLimit int
	// run replaces the single action for a route Keeper composes itself
	// (several actions, or none). It gets the decoded input and the opened
	// request, whose session a lease-aware route needs.
	run func(s *Server, request appRequest, input any) (proto.BaseResponse, error)
}

var errAppRouteRefused = errors.New("request refused by the App route")

// appRoutes is every fixed App route. The table is split by domain; a path
// registered twice is a programming error caught at start-up.
var appRoutes = mergeAppRoutes(authAndGroupRoutes, chatRoutes(), peerKeyRoutes, archiveRoutes, accountRoutes, groupHandleRoutes, passwordRoutes)

func mergeAppRoutes(tables ...map[string]appRoute) map[string]appRoute {
	merged := map[string]appRoute{}
	for _, table := range tables {
		for path, route := range table {
			if _, dup := merged[path]; dup {
				panic("localrpc: App route registered twice: " + path)
			}
			merged[path] = route
		}
	}
	return merged
}

var authAndGroupRoutes = map[string]appRoute{
	"/v1/auth/recovery/begin": {
		action: proto.ActionAuthRecoveryBegin,
		input:  func() any { return &proto.AuthRecoveryBeginRequest{} },
	},
	"/v1/auth/recovery/prepare": {
		action: proto.ActionAuthRecoveryPrepare,
		input:  func() any { return &proto.AuthRecoveryPrepareRequest{} },
	},
	"/v1/auth/signup/abort": {
		action: proto.ActionAuthSignupAbort,
		input:  func() any { return &proto.AuthSignupAbortRequest{} },
	},
	"/v1/auth/recovery/abort": {
		action: proto.ActionAuthRecoveryAbort,
		input:  func() any { return &proto.AuthRecoveryAbortRequest{} },
	},
	"/v1/auth/recovery/close": {
		action: proto.ActionRecoverySessionClose,
		input:  func() any { return &proto.RecoverySessionCloseRequest{} },
	},
	"/v1/auth/recovery/rewrap-group-dek": {
		action: proto.ActionDEKRewrapWithOldKeyToSelf,
		input:  func() any { return &proto.DEKRewrapWithOldKeyToSelfRequest{} },
	},
	"/v1/account-key/public": {
		action: proto.ActionGetPublicKey,
		input:  func() any { return &struct{}{} },
	},
	"/v1/key-transparency/status": {
		action: proto.ActionKeyTransparencyStatus,
		input:  func() any { return &proto.KeyTransparencyStatusRequest{} },
	},
	"/v1/peer-key/pin": {
		action: proto.ActionPeerKeyPinGet,
		input:  func() any { return &proto.PeerKeyPinGetRequest{} },
	},
	"/v1/group-dek/generate": {
		action: proto.ActionGroupDEKGenerateAndOpen,
		input:  func() any { return &struct{}{} },
		bind:   bindGenerateToOwnKey,
	},
	"/v1/group-dek/close": {
		action: proto.ActionGroupSessionClose,
		input:  func() any { return &proto.GroupSessionCloseRequest{} },
	},
	"/v1/group-dek/rewrap-for-member": {
		action:     proto.ActionDEKRewrapForMember,
		input:      func() any { return &appMemberRewrap{} },
		bind:       bindMemberRewrap,
		plainLimit: proto.DEKRewrapMaxRequestBytes,
	},
	"/v1/group-dek/rewrap-for-many": {
		action:     proto.ActionDEKUnwrapAndRewrapForMany,
		input:      func() any { return &appManyRewrap{} },
		bind:       bindManyRewrap,
		plainLimit: proto.DEKRewrapMaxRequestBytes,
	},
}

// appMemberRewrap always names both accounts, so the pin is always enforced.
type appMemberRewrap struct {
	WrappedForMeB64    string                       `json:"wrapped_for_me_b64"`
	OtherPublicKey     string                       `json:"other_public_key"`
	OwnerAccountID     string                       `json:"owner_account_id"`
	OtherAccountID     string                       `json:"other_account_id"`
	RotationStatements []proto.KeyRotationStatement `json:"rotation_statements,omitempty"`
}

type appManyRewrap struct {
	WrappedForMeB64 string             `json:"wrapped_for_me_b64"`
	OwnerAccountID  string             `json:"owner_account_id"`
	Recipients      []appManyRecipient `json:"recipients"`
}

// appManyRecipient without an account id is pin-exempt, as it is on the
// Native Messaging path: either this Keeper's own key (checked here against
// the active key) or the org archive key, which is an org resource with no
// account to pin (threat model §4.11 accepted gap).
type appManyRecipient struct {
	AccountID          string                       `json:"account_id,omitempty"`
	PublicKey          string                       `json:"public_key"`
	RotationStatements []proto.KeyRotationStatement `json:"rotation_statements,omitempty"`
	OrgArchive         bool                         `json:"org_archive,omitempty"`
}

func bindGenerateToOwnKey(s *Server, _ any) (any, error) {
	own, err := s.ownPublicKey()
	if err != nil {
		return nil, err
	}
	return proto.GroupDEKGenerateAndOpenRequest{MyPublicKey: own}, nil
}

func bindMemberRewrap(_ *Server, input any) (any, error) {
	in := input.(*appMemberRewrap)
	if in.OwnerAccountID == "" || in.OtherAccountID == "" {
		return nil, errAppRouteRefused
	}
	return proto.DEKRewrapForMemberRequest{
		WrappedForMeB64:    in.WrappedForMeB64,
		OtherPublicKey:     in.OtherPublicKey,
		OwnerAccountID:     in.OwnerAccountID,
		OtherAccountID:     in.OtherAccountID,
		RotationStatements: in.RotationStatements,
	}, nil
}

func bindManyRewrap(s *Server, input any) (any, error) {
	in := input.(*appManyRewrap)
	if in.OwnerAccountID == "" || len(in.Recipients) == 0 {
		return nil, errAppRouteRefused
	}
	own := ""
	archives := 0
	recipients := make([]proto.DEKRewrapRecipient, 0, len(in.Recipients))
	for _, recipient := range in.Recipients {
		switch {
		case recipient.AccountID != "":
			if recipient.OrgArchive {
				return nil, errAppRouteRefused
			}
		case recipient.OrgArchive:
			archives++
			if archives > 1 || len(recipient.RotationStatements) > 0 {
				return nil, errAppRouteRefused
			}
		default:
			if own == "" {
				key, err := s.ownPublicKey()
				if err != nil {
					return nil, err
				}
				own = key
			}
			if recipient.PublicKey != own || len(recipient.RotationStatements) > 0 {
				return nil, errAppRouteRefused
			}
		}
		recipients = append(recipients, proto.DEKRewrapRecipient{
			AccountID:          recipient.AccountID,
			PublicKey:          recipient.PublicKey,
			RotationStatements: recipient.RotationStatements,
		})
	}
	return proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: in.WrappedForMeB64,
		OwnerAccountID:  in.OwnerAccountID,
		Recipients:      recipients,
	}, nil
}

// ownPublicKey is this Keeper's active account public key, read through the
// same action the App could call, so the route holds no keychain access of
// its own.
func (s *Server) ownPublicKey() (string, error) {
	response, err := s.handle("", proto.ActionGetPublicKey, nil)
	if err != nil || !response.Success {
		return "", errAppRouteRefused
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return "", err
	}
	var data proto.GetPublicKeyResponseData
	if err := json.Unmarshal(encoded, &data); err != nil || data.PublicKey == "" {
		return "", errAppRouteRefused
	}
	return data.PublicKey, nil
}

func (s *Server) serveAppRoute(w http.ResponseWriter, r *http.Request, route appRoute) {
	request, ok := s.openAppRequest(w, r)
	if !ok {
		return
	}
	input := route.input()
	decoder := json.NewDecoder(bytes.NewReader(request.plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var response proto.BaseResponse
	var err error
	switch {
	case route.run != nil:
		response, err = route.run(s, request, input)
	case route.bind != nil:
		var bound any
		if bound, err = route.bind(s, input); err == nil {
			var encoded []byte
			if encoded, err = json.Marshal(bound); err == nil {
				response, err = s.handleRequest(request, route.action, encoded)
			}
		}
	default:
		// The action gets the bytes the App sent, not a re-encoding: the
		// chat handlers decode strictly (duplicate keys, missing keys) and a
		// round trip through the route type would hide both.
		response, err = s.handleRequest(request, route.action, request.plain)
	}
	if errors.Is(err, errSessionGone) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	s.writeSealed(w, request, response)
}

// appPlainLimit is the opened-request cap for a path.
func appPlainLimit(path string) int {
	if route, ok := appRoutes[path]; ok && route.plainLimit > 0 {
		return route.plainLimit
	}
	return maxRequestBytes
}

// appSealedLimit bounds the sealed body read for a path: base64 growth of
// the plaintext cap plus framing.
func appSealedLimit(path string) int64 {
	return int64(appPlainLimit(path))*4/3 + 512
}
