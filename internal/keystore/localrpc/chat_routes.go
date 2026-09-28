package localrpc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// errSessionGone means the session was closed between opening the request
// and acting on it; the App sees the same 401 it gets for an unknown session.
var errSessionGone = errors.New("local session is gone")

// longWriteRoute names the routes whose answer can take far longer than the
// default write deadline: a room create verifying 32 KeyPackages and their
// transparency evidence, a 200-message display batch, a chat call queued
// behind an Extension request on the request lock, and the big wrap
// fan-outs. The Extension's Native Messaging wrappers allow 30 s for them.
func longWriteRoute(path string) bool {
	if _, ok := appRoutes[path]; !ok {
		return false
	}
	switch path {
	case "/v1/peer-key/chain-evaluate", "/v1/archive/archive_key_split", "/v1/archive/archive_quorum_combine_and_rewrap":
		return true
	}
	return strings.HasPrefix(path, "/v1/chat/")
}

// chatActionRoute exposes one chat action at /v1/chat/<action> with the
// action's own request type and the cap its handler enforces, so the route
// never refuses what the handler would take nor lets through more.
func chatActionRoute(action string, input func() any, limit int) (string, appRoute) {
	return "/v1/chat/" + action, appRoute{action: action, input: input, plainLimit: limit}
}

// chatRoutes is the App's chat surface. Whether an action needs the chat
// runtime lease is decided in keystore (chat_runtime.go) for every caller,
// not here.
func chatRoutes() map[string]appRoute {
	const (
		mlsCap     = proto.MLSChatMaxRequestBytes
		stateCap   = proto.ChatStateMaxRequestBytes
		displayCap = proto.MLSDecryptMaxRequestBytes
	)
	routes := map[string]appRoute{
		"/v1/chat/capability": {
			input: func() any { return &struct{}{} },
			run:   runChatCapability,
		},
		"/v1/chat/runtime/claim": {
			input: func() any { return &chatRuntimeClaimInput{} },
			run:   runChatRuntimeClaim,
		},
		"/v1/chat/runtime/release": {
			input: func() any { return &chatRuntimeHolder{} },
			run:   runChatRuntimeRelease,
		},
		"/v1/chat/room_row_name_seal": {
			input: func() any { return &roomRowNameSeal{} },
			run:   runRoomRowNameSeal,
		},
	}
	for _, r := range []struct {
		action string
		input  func() any
		limit  int
	}{
		{proto.MLSGroupCreate, func() any { return &proto.MLSGroupCreateRequest{} }, mlsCap},
		{proto.MLSGroupDiscardUnaccepted, func() any { return &proto.MLSGroupDiscardUnacceptedRequest{} }, stateCap},
		{proto.MLSConversationForgetRemoved, func() any { return &proto.MLSConversationForgetRemovedRequest{} }, stateCap},
		{proto.MLSCommitBuild, func() any { return &proto.MLSCommitBuildRequest{} }, mlsCap},
		{proto.MLSCommitConfirm, func() any { return &proto.MLSCommitConfirmRequest{} }, mlsCap},
		{proto.MLSProcess, func() any { return &proto.MLSProcessRequest{} }, mlsCap},
		{proto.MLSJoin, func() any { return &proto.MLSJoinRequest{} }, mlsCap},
		{proto.MLSEncrypt, func() any { return &proto.MLSEncryptRequest{} }, stateCap},
		{proto.MLSMarkSent, func() any { return &proto.MLSMarkSentRequest{} }, stateCap},
		{proto.MLSDecryptBatchForAppDisplay, func() any { return &proto.MLSDecryptBatchForAppDisplayRequest{} }, displayCap},
		{proto.MLSRoomNameSeal, func() any { return &proto.MLSRoomNameSealRequest{} }, stateCap},
		{proto.MLSRoomNameOpen, func() any { return &proto.MLSRoomNameOpenRequest{} }, stateCap},
		{proto.MLSConversationStatus, func() any { return &proto.MLSConversationStatusRequest{} }, stateCap},
		{proto.MLSRejoinRequestSign, func() any { return &proto.MLSRejoinRequestSignRequest{} }, stateCap},
		{proto.MLSCommitAbandon, func() any { return &proto.MLSCommitAbandonRequest{} }, stateCap},
		{proto.MLSLeaveRequestSign, func() any { return &proto.MLSLeaveRequestSignRequest{} }, stateCap},
		{proto.ChatStateReadOutbox, func() any { return &proto.ChatStateReadOutboxRequest{} }, stateCap},
		{proto.ChatStatePurge, func() any { return &proto.ChatStatePurgeRequest{} }, stateCap},
		// The leaf, KeyPackage and statement actions decode leniently and have
		// no cap of their own; their fixed-field requests fit the chat state
		// cap with room to spare.
		{proto.ActionMLSLeafStatus, func() any { return &proto.MLSLeafStatusRequest{} }, stateCap},
		{proto.ActionMLSLeafDeclare, func() any { return &proto.MLSLeafDeclareRequest{} }, stateCap},
		{proto.ActionMLSLeafPromote, func() any { return &proto.MLSLeafPromoteRequest{} }, stateCap},
		{proto.ActionMLSLeafAbort, func() any { return &proto.MLSLeafAbortRequest{} }, stateCap},
		{proto.ActionMLSLeafHandoverSign, func() any { return &proto.MLSLeafHandoverSignRequest{} }, stateCap},
		{proto.MLSKeyPackageGenerate, func() any { return &proto.MLSKeyPackageGenerateRequest{} }, stateCap},
		{proto.MLSKeyPackagePoolSweep, func() any { return &proto.MLSKeyPackagePoolSweepRequest{} }, stateCap},
		{proto.OrgMemberRemovalSign, func() any { return &proto.OrgMemberRemovalSignRequest{} }, stateCap},
		{proto.MLSDeviceRevokeSign, func() any { return &proto.MLSDeviceRevokeSignRequest{} }, stateCap},
	} {
		path, route := chatActionRoute(r.action, r.input, r.limit)
		routes[path] = route
	}
	return routes
}

// runChatCapability is ping without the binary path, which the App does not
// need and /v1/health keeps to itself as well.
func runChatCapability(s *Server, request appRequest, _ any) (proto.BaseResponse, error) {
	response, err := s.handle(request.token, proto.ActionPing, nil)
	if err != nil || !response.Success {
		return response, err
	}
	var data proto.PingResponseData
	if err := remarshal(response.Data, &data); err != nil {
		return proto.BaseResponse{}, err
	}
	return proto.BaseResponse{Success: true, Data: map[string]any{
		"version":           data.Version,
		"hash":              data.Hash,
		"chat_contract":     data.ChatContract,
		"chat_capabilities": data.ChatCapabilities,
	}}, nil
}

type chatRuntimeHolder struct {
	HolderID string `json:"holder_id"`
}

var holderIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

func (h *chatRuntimeHolder) valid() bool { return holderIDPattern.MatchString(h.HolderID) }

// chatRuntimeClaimInput carries the epoch a running runtime already holds, so
// a re-claim after a revocation is refused instead of handing it a new one.
type chatRuntimeClaimInput struct {
	chatRuntimeHolder
	Epoch string `json:"epoch,omitempty"`
}

// runChatRuntimeClaim binds the lease to the calling session under s.mu, so a
// session deleted at the same moment cannot leave a lease behind it.
func runChatRuntimeClaim(s *Server, request appRequest, input any) (proto.BaseResponse, error) {
	holder := input.(*chatRuntimeClaimInput)
	if !holder.valid() || (holder.Epoch != "" && !chatRuntimeEpochPattern.MatchString(holder.Epoch)) {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	s.mu.Lock()
	current, ok := s.sessions[request.token]
	now := s.now()
	if !ok || !now.Before(current.expires) {
		s.mu.Unlock()
		return proto.BaseResponse{}, errSessionGone
	}
	claim := s.app.ClaimChatRuntime(holder.HolderID, request.token, current.expires.Sub(now), holder.Epoch)
	s.mu.Unlock()
	if claim.Revoked != "" {
		return keystore.ChatRuntimeRevokedResponse(claim.Revoked), nil
	}
	if !claim.Granted {
		return proto.BaseResponse{
			Error:     "the chat runtime is held elsewhere on this device",
			ErrorCode: keystore.ErrCodeChatRuntimeBusy,
			Data:      map[string]string{"holder": claim.BusyHolder},
		}, nil
	}
	return proto.BaseResponse{Success: true, Data: map[string]any{
		"expires_at":  claim.ExpiresAt.Unix(),
		"ttl_seconds": int64(claim.ExpiresAt.Sub(s.app.Clock()).Seconds()),
		"epoch":       claim.Epoch,
	}}, nil
}

func runChatRuntimeRelease(s *Server, _ appRequest, input any) (proto.BaseResponse, error) {
	holder := input.(*chatRuntimeHolder)
	if !holder.valid() {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	return proto.BaseResponse{Success: true, Data: map[string]bool{
		"released": s.app.ReleaseChatRuntime(holder.HolderID),
	}}, nil
}

// roomRowNameSeal is the name a room row is created with on the server. The
// real name travels MLS-sealed; this copy is sealed under a Group DEK that is
// generated, used once and dropped, the way the Extension does it
// (chat-runtime.ts sealRoomNameOnce). There is no handle and no AAD input, so
// the route cannot be turned into a general encrypt.
type roomRowNameSeal struct {
	OrgID          string `json:"org_id"`
	ConversationID string `json:"conversation_id"`
	PlaintextB64   string `json:"plaintext_b64"`
}

const (
	roomRowNameSealDEKVersion = "1"
	roomNameMaxBytes          = 256
	nilUUID                   = "00000000-0000-0000-0000-000000000000"
)

func runRoomRowNameSeal(s *Server, request appRequest, input any) (proto.BaseResponse, error) {
	in := input.(*roomRowNameSeal)
	for _, id := range []string{in.OrgID, in.ConversationID} {
		if !validUUID(id) || id == nilUUID {
			return proto.BaseResponse{}, errAppRouteRefused
		}
	}
	name, err := base64.StdEncoding.DecodeString(in.PlaintextB64)
	if err != nil || len(name) == 0 || len(name) > roomNameMaxBytes || !utf8.Valid(name) {
		secure.Zeroize(name)
		return proto.BaseResponse{}, errAppRouteRefused
	}
	secure.Zeroize(name)

	own, err := s.ownPublicKey()
	if err != nil {
		return proto.BaseResponse{}, err
	}
	generate, _ := json.Marshal(proto.GroupDEKGenerateAndOpenRequest{MyPublicKey: own})
	generated, err := s.handle(request.token, proto.ActionGroupDEKGenerateAndOpen, generate)
	if err != nil || !generated.Success {
		return generated, err
	}
	var opened proto.GroupDEKGenerateAndOpenResponseData
	if err := remarshal(generated.Data, &opened); err != nil || opened.GroupHandle == "" {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	defer func() {
		closeRequest, _ := json.Marshal(proto.GroupSessionCloseRequest{GroupHandle: opened.GroupHandle})
		_, _ = s.handle(request.token, proto.ActionGroupSessionClose, closeRequest)
	}()

	aad := "dragpass.room|1|" + in.OrgID + "|" + in.ConversationID + "|" + roomRowNameSealDEKVersion
	encrypt, _ := json.Marshal(proto.GroupEncryptWithAADRequest{
		GroupHandle:  opened.GroupHandle,
		PlaintextB64: in.PlaintextB64,
		AADB64:       base64.StdEncoding.EncodeToString([]byte(aad)),
	})
	sealed, err := s.handle(request.token, proto.ActionGroupEncryptWithAAD, encrypt)
	if err != nil || !sealed.Success {
		return sealed, err
	}
	var data proto.GroupEncryptResponseData
	if err := remarshal(sealed.Data, &data); err != nil || data.IVB64 == "" || data.CiphertextB64 == "" {
		return proto.BaseResponse{}, errAppRouteRefused
	}
	return proto.BaseResponse{Success: true, Data: map[string]string{
		"iv_b64":         data.IVB64,
		"ciphertext_b64": data.CiphertextB64,
	}}, nil
}

func remarshal(from, into any) error {
	raw, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// peerKeyRoutes is the key-trust panel. The requests are the actions' own;
// what they let the App do (verify, turn strict mode off) is what the
// Extension's panel does, under the App-origin limit of threat model §4.12.
// peer_key_pin_forget is left out: forgetting a pin re-TOFUs a changed key,
// and the key-trust UI no longer offers it (MLS hardening policy Q9 (a)).
var peerKeyRoutes = map[string]appRoute{
	"/v1/peer-key/pin-list": {
		action: proto.ActionPeerKeyPinList,
		input:  func() any { return &proto.PeerKeyPinListRequest{} },
	},
	"/v1/peer-key/pin-verify": {
		action: proto.ActionPeerKeyPinVerify,
		input:  func() any { return &proto.PeerKeyPinVerifyRequest{} },
	},
	"/v1/peer-key/safety-number": {
		action: proto.ActionPeerKeySafetyNumber,
		input:  func() any { return &proto.PeerKeySafetyNumberRequest{} },
	},
	"/v1/peer-key/chain-evaluate": {
		action:     proto.ActionPeerKeyChainEvaluate,
		input:      func() any { return &proto.PeerKeyChainEvaluateRequest{} },
		plainLimit: proto.DEKRewrapMaxRequestBytes,
	},
	"/v1/peer-key/policy-get": {
		action: proto.ActionPeerKeyPolicyGet,
		input:  func() any { return &proto.PeerKeyPolicyGetRequest{} },
	},
	"/v1/peer-key/policy-set": {
		action: proto.ActionPeerKeyPolicySet,
		input:  func() any { return &proto.PeerKeyPolicySetRequest{} },
	},
}

// archiveRoutes is the org archive key, break-glass and quorum surface.
// Recipients that are member account keys (a break-glass re-grant, a quorum
// combine) must name their accounts, so Keeper judges each against its peer
// key pin as rewrap-for-member does, and a changed key refuses. The rest name
// keys no pin tracks, and stay the threat model §4.11 accepted gap: an
// ownership handoff and a split go to account archive keys, and a share
// rewrap to the ephemeral key of a recovery session. The one target Keeper
// knows itself, the staged key of a rotation, is bound here.
var archiveRoutes = map[string]appRoute{
	"/v1/archive/archive_key_generate":         archiveEmptyRoute(proto.ActionArchiveKeyGenerate),
	"/v1/archive/archive_key_status":           archiveEmptyRoute(proto.ActionArchiveKeyStatus),
	"/v1/archive/account_archive_key_generate": archiveEmptyRoute(proto.ActionAccountArchiveKeyGenerate),
	"/v1/archive/account_archive_key_status":   archiveEmptyRoute(proto.ActionAccountArchiveKeyStatus),
	"/v1/archive/archive_key_rotate_begin":     archiveEmptyRoute(proto.ActionArchiveKeyRotateBegin),
	"/v1/archive/archive_key_rotate_commit":    archiveEmptyRoute(proto.ActionArchiveKeyRotateCommit),
	"/v1/archive/archive_key_rotate_abort":     archiveEmptyRoute(proto.ActionArchiveKeyRotateAbort),
	"/v1/archive/archive_session_begin":        archiveEmptyRoute(proto.ActionArchiveSessionBegin),
	"/v1/archive/archive_session_end":          archiveEmptyRoute(proto.ActionArchiveSessionEnd),
	"/v1/archive/archive_unwrap_and_rewrap": {
		action:     proto.ActionArchiveUnwrapAndRewrap,
		input:      func() any { return &appArchiveRewrap{} },
		bind:       bindArchiveRewrap,
		plainLimit: proto.ChatStateMaxRequestBytes,
	},
	"/v1/archive/archive_key_split": {
		action:     proto.ActionArchiveKeySplit,
		input:      func() any { return &proto.ArchiveKeySplitRequest{} },
		plainLimit: proto.DEKRewrapMaxRequestBytes,
	},
	"/v1/archive/archive_share_rewrap": {
		action:     proto.ActionArchiveShareRewrap,
		input:      func() any { return &proto.ArchiveShareRewrapRequest{} },
		plainLimit: proto.ChatStateMaxRequestBytes,
	},
	"/v1/archive/archive_quorum_combine_and_rewrap": {
		action:     proto.ActionArchiveQuorumCombineAndRewrap,
		input:      func() any { return &appQuorumCombine{} },
		bind:       bindQuorumCombine,
		plainLimit: proto.DEKRewrapMaxRequestBytes,
	},
}

func archiveEmptyRoute(action string) appRoute {
	return appRoute{action: action, input: func() any { return &struct{}{} }}
}

// appArchiveRewrap names its target, exactly one of: the staged archive key
// of a rotation in progress, which Keeper reads itself; a member's account key
// for a break-glass re-grant, with both account ids so the pin is enforced;
// or the new owner's account archive key for an ownership handoff.
type appArchiveRewrap struct {
	WrappedForArchiveB64    string                       `json:"wrapped_for_archive_b64"`
	ToStagedArchiveKey      bool                         `json:"to_staged_archive_key,omitempty"`
	RecipientPublicKey      string                       `json:"recipient_public_key,omitempty"`
	OwnerAccountID          string                       `json:"owner_account_id,omitempty"`
	RecipientAccountID      string                       `json:"recipient_account_id,omitempty"`
	RotationStatements      []proto.KeyRotationStatement `json:"rotation_statements,omitempty"`
	AccountArchivePublicKey string                       `json:"account_archive_public_key,omitempty"`
}

func bindArchiveRewrap(s *Server, input any) (any, error) {
	in := input.(*appArchiveRewrap)
	member := in.RecipientPublicKey != ""
	handoff := in.AccountArchivePublicKey != ""
	named := in.OwnerAccountID != "" || in.RecipientAccountID != "" || len(in.RotationStatements) > 0
	targets := 0
	for _, chosen := range []bool{in.ToStagedArchiveKey, member, handoff} {
		if chosen {
			targets++
		}
	}
	if targets != 1 || named != member || (member && (in.OwnerAccountID == "" || in.RecipientAccountID == "")) {
		return nil, errAppRouteRefused
	}
	if member {
		return proto.ArchiveUnwrapAndRewrapRequest{
			WrappedForArchiveB64: in.WrappedForArchiveB64,
			RecipientPublicKey:   in.RecipientPublicKey,
			OwnerAccountID:       in.OwnerAccountID,
			RecipientAccountID:   in.RecipientAccountID,
			RotationStatements:   in.RotationStatements,
		}, nil
	}
	target := in.AccountArchivePublicKey
	if in.ToStagedArchiveKey {
		// A public key, read without the request lock: a rotate_begin that
		// lands in between restages, and this grant goes to the key the App
		// no longer holds a fingerprint for. The App's rotation already
		// fails in that case, since its begin answer named the old one.
		staged, err := keychain.GetArchiveStagingPublicKey(s.app.Store)
		if err != nil || staged == "" {
			return nil, errAppRouteRefused
		}
		target = staged
	}
	return proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: in.WrappedForArchiveB64,
		RecipientPublicKey:   target,
	}, nil
}

// appQuorumCombine is the combine with only the pin-carrying recipient list:
// every re-grant target names its account.
type appQuorumCombine struct {
	RewrappedShares  []proto.RewrappedShareInput `json:"rewrapped_shares"`
	WrappedOldDEKB64 string                      `json:"wrapped_old_dek_b64"`
	OwnerAccountID   string                      `json:"owner_account_id"`
	Recipients       []proto.DEKRewrapRecipient  `json:"recipients"`
}

func bindQuorumCombine(_ *Server, input any) (any, error) {
	in := input.(*appQuorumCombine)
	if in.OwnerAccountID == "" || len(in.Recipients) == 0 {
		return nil, errAppRouteRefused
	}
	for _, recipient := range in.Recipients {
		if recipient.AccountID == "" {
			return nil, errAppRouteRefused
		}
	}
	return proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares:  in.RewrappedShares,
		WrappedOldDEKB64: in.WrappedOldDEKB64,
		OwnerAccountID:   in.OwnerAccountID,
		Recipients:       in.Recipients,
	}, nil
}
