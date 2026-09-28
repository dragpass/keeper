package localrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/version"
)

const maxRequestBytes = 8 * 1024

const maxSessionNonces = 4096
const maxNativeMessageBytes = dispatch.MaxMessageSize

// Version 2 seals every proxied message to a proven owner instance. A v1
// listener cannot answer the health challenge, so a v2 host runs standalone.
const nativeProxyProtocolVersion = 2

const DefaultAddress = "127.0.0.1:47623"

// AddressEnvVar moves an isolated test Keeper to another loopback port so a
// real-process test never touches a Keeper the developer is running. The App
// only ever talks to DefaultAddress.
const AddressEnvVar = "DRAGPASS_KEEPER_LOCAL_ADDRESS"

// Address is DefaultAddress unless an isolated test asked for another
// 127.0.0.1 port.
func Address(isolated bool, getenv func(string) string) (string, error) {
	override := strings.TrimSpace(getenv(AddressEnvVar))
	if override == "" {
		return DefaultAddress, nil
	}
	host, port, err := net.SplitHostPort(override)
	if !isolated || err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		return "", fmt.Errorf("%s must be a 127.0.0.1 port and needs an isolated e2e Keeper", AddressEnvVar)
	}
	return override, nil
}

const NativeExtensionOrigin = "chrome-extension://cmgjlocmnppfpknaipdfodjhbplnhimk"

// DevAppOriginEnvVar opts one development App origin in. Production binaries
// trust only the deployed App, so a page any local program serves on a dev
// port cannot drive Keeper.
const DevAppOriginEnvVar = "DRAGPASS_KEEPER_DEV_APP_ORIGIN"

func AppOrigins(getenv func(string) string) []string {
	origins := []string{"https://app.dragpass.io", NativeExtensionOrigin}
	if dev := strings.TrimSpace(getenv(DevAppOriginEnvVar)); dev != "" {
		origins = append(origins, dev)
	}
	return origins
}

type Server struct {
	app        *keystore.App
	origins    map[string]struct{}
	host       string
	now        func() time.Time
	secret     localsecret.Secret
	appKey     []byte
	proxy      *proxyReceiver
	mu         sync.Mutex
	sessions   map[string]session
	challenges map[string]time.Time
}

type session struct {
	csrf    string
	expires time.Time
	nonces  map[string]time.Time
	// key seals every request and response of this session (channel.go).
	key    []byte
	origin string
	sealed map[string]struct{}
}

type requestSignature struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
	AccountID  string `json:"account_id"`
	TokenID    string `json:"token_id"`
	DeviceID   string `json:"device_id"`
}

func New(app *keystore.App, origins []string, secret localsecret.Secret) (*Server, error) {
	if secret.IsZero() {
		return nil, errors.New("local RPC requires the Keeper local secret")
	}
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid local RPC origin %q", origin)
		}
		allowed[origin] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one local RPC origin is required")
	}
	instance, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Server{
		app:        app,
		origins:    allowed,
		now:        time.Now,
		secret:     secret,
		appKey:     secret.AppPairingKey(),
		proxy:      &proxyReceiver{key: secret.NativeProxyKey(), instance: instance, seen: make(map[string]time.Time)},
		sessions:   make(map[string]session),
		challenges: make(map[string]time.Time),
	}, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func Listen() (net.Listener, error) {
	return net.Listen("tcp4", DefaultAddress)
}

func (s *Server) Serve(ctx context.Context) error {
	listener, err := Listen()
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, listener)
}

func (s *Server) ServeListener(ctx context.Context, listener net.Listener) error {
	s.host = listener.Addr().String()
	server := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       8 * time.Second,
		WriteTimeout:      8 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if _, ok := s.origins[origin]; !ok || r.Host != s.host || !isLoopbackRemote(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-DragPass-Local-RPC, X-DragPass-CSRF, Authorization")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Header.Get("X-DragPass-Local-RPC") != "1" || !isAppFetch(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		maxBytes := appSealedLimit(r.URL.Path)
		if r.URL.Path == "/v1/native-proxy/message" {
			maxBytes = sealedLimit()
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if r.URL.Path != "/v1/health" {
		if err := s.refreshSecret(); err != nil {
			http.Error(w, "local secret unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
		writeJSON(w, http.StatusOK, map[string]any{
			"version": version.Version,
			"hash":    version.BinaryHash,
		})
	case origin == NativeExtensionOrigin && r.Method == http.MethodGet && r.URL.Path == "/v1/native-proxy/health":
		challenge := r.URL.Query().Get("challenge")
		if !validNonce(challenge, 16) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version":          version.Version,
			"hash":             version.BinaryHash,
			"protocol_version": nativeProxyProtocolVersion,
			"instance":         s.proxy.instance,
			"proof":            base64.RawURLEncoding.EncodeToString(healthProof(s.proxy.currentKey(), challenge, s.proxy.instance)),
		})
	case origin == NativeExtensionOrigin && r.Method == http.MethodPost && r.URL.Path == "/v1/native-proxy/message":
		s.serveNativeProxyMessage(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session/challenge":
		s.issueChallenge(w)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
		s.openSession(w, r, origin)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/session":
		s.closeSession(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/status":
		s.serveStatus(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/request-signature":
		s.signRequest(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/sign-alias":
		s.dispatchAppAuthAction(w, r, proto.ActionSignAliasWithTimestamp, func() any {
			return &proto.SignAliasWithTimestampRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/sign-challenge":
		s.dispatchAppAuthAction(w, r, proto.ActionSignChallengeToken, func() any {
			return &proto.SignChallengeTokenRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/pending/sign-alias":
		s.dispatchAppAuthAction(w, r, proto.ActionAuthLoginPendingSignAlias, func() any {
			return &proto.AuthLoginPendingSignAliasRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/pending/sign-challenge":
		s.dispatchAppAuthAction(w, r, proto.ActionAuthLoginPendingSignChallenge, func() any {
			return &proto.AuthLoginPendingSignChallengeRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/restore-device-master":
		s.dispatchAppAuthActionWithoutResult(w, r, proto.ActionDEKRotateToDeviceKey, func() any {
			return &proto.DEKRotateToDeviceKeyRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/ensure-request-key":
		s.dispatchAppAuthAction(w, r, proto.ActionRequestKeyGenerate, func() any {
			return &proto.RequestKeyGenerateRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/signup/prepare":
		s.dispatchAppAuthAction(w, r, proto.ActionAuthSignupPrepare, func() any {
			return &proto.AuthSignupPrepareRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/recovery-key/reissue-prepare":
		s.dispatchAppAuthAction(w, r, proto.ActionAuthRecoveryReissuePrepare, func() any {
			return &proto.AuthRecoveryReissuePrepareRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/signup/save-session-code":
		s.dispatchAppAuthActionWithoutResult(w, r, proto.ActionSaveSessionCode, func() any {
			return &proto.SaveSessionCodeRequest{}
		})
	case r.Method == http.MethodPost && appRoutes[r.URL.Path].action != "":
		s.serveAppRoute(w, r, appRoutes[r.URL.Path])
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) dispatchAppAuthAction(w http.ResponseWriter, r *http.Request, action string, newPayload func() any) {
	s.dispatchAppAction(w, r, action, newPayload, false)
}

func (s *Server) dispatchAppAuthActionWithoutResult(w http.ResponseWriter, r *http.Request, action string, newPayload func() any) {
	s.dispatchAppAction(w, r, action, newPayload, true)
}

func (s *Server) dispatchAppAction(w http.ResponseWriter, r *http.Request, action string, newPayload func() any, suppressResult bool) {
	request, ok := s.openAppRequest(w, r)
	if !ok {
		return
	}
	input := newPayload()
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
	payload, err := json.Marshal(input)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := s.handle(action, payload)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if suppressResult && response.Success {
		// Which stage a save promoted is not secret, and the App needs it to
		// tell a recovery (grants to re-share) from a signup; the session
		// code itself stays in Keeper.
		if saved, ok := response.Data.(proto.SaveSessionCodeResponseData); ok {
			response.Data = map[string]any{"stored": true, "promoted": saved.Promoted}
		} else {
			response.Data = map[string]bool{"stored": true}
		}
	}
	s.writeSealed(w, request, response)
}

// appRequest is one opened, authenticated App request.
type appRequest struct {
	session session
	token   string
	path    string
	nonce   string
	plain   []byte
}

// openAppRequest authenticates the session, opens the sealed body and refuses
// a replayed envelope. Every answer that is not a sealed 200 is a failure the
// App cannot mistake for the owner's result.
func (s *Server) openAppRequest(w http.ResponseWriter, r *http.Request) (appRequest, bool) {
	defer r.Body.Close()
	token := bearerToken(r)
	now := s.now()
	s.mu.Lock()
	current, ok := s.sessions[token]
	if !ok || !now.Before(current.expires) {
		delete(s.sessions, token)
		s.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return appRequest{}, false
	}
	validCSRF := constantTimeEqual(r.Header.Get("X-DragPass-CSRF"), current.csrf)
	s.mu.Unlock()
	if !validCSRF || r.Header.Get("Origin") != current.origin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return appRequest{}, false
	}
	var envelope sealedEnvelope
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Nonce == "" || envelope.Sealed == "" ||
		envelope.Instance != "" || envelope.Timestamp != 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return appRequest{}, false
	}
	plain, err := openEnvelope(current.key, envelope, appRequestAAD(current.origin, token, r.URL.Path))
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return appRequest{}, false
	}
	if len(plain) > appPlainLimit(r.URL.Path) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return appRequest{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok = s.sessions[token]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return appRequest{}, false
	}
	if _, replay := current.sealed[envelope.Nonce]; replay {
		http.Error(w, "replayed request", http.StatusConflict)
		return appRequest{}, false
	}
	if len(current.sealed) >= maxSessionNonces {
		http.Error(w, "session request limit reached", http.StatusTooManyRequests)
		return appRequest{}, false
	}
	current.sealed[envelope.Nonce] = struct{}{}
	return appRequest{session: current, token: token, path: r.URL.Path, nonce: envelope.Nonce, plain: plain}, true
}

// writeSealed answers under the session key, bound to the request it answers.
func (s *Server) writeSealed(w http.ResponseWriter, request appRequest, response proto.BaseResponse) {
	plain, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sealed, err := sealEnvelope(request.session.key, appResponseAAD(request.session.origin, request.token, request.path, request.nonce), plain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sealed)
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	request, ok := s.openAppRequest(w, r)
	if !ok {
		return
	}
	if !bytes.Equal(bytes.TrimSpace(request.plain), []byte("{}")) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := s.handle("request_key_status", nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.writeSealed(w, request, response)
}

func (s *Server) serveNativeProxyMessage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	message, requestNonce, proxyKey, err := s.proxy.open(body, s.now())
	if errors.Is(err, errStaleProxyInstance) {
		http.Error(w, "owner changed", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	response, err := json.Marshal(s.app.HandleRequest(message))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sealed, err := sealProxyResponse(proxyKey, s.proxy.instance, requestNonce, response)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

// issueChallenge hands out a one-time value the App must prove over. A proof
// over the owner's own challenge cannot be captured by a port squatter and
// replayed to the real owner later.
func (s *Server) issueChallenge(w http.ResponseWriter) {
	challenge, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := s.now()
	s.mu.Lock()
	for value, expires := range s.challenges {
		if !now.Before(expires) {
			delete(s.challenges, value)
		}
	}
	if len(s.challenges) >= maxAppChallenges {
		s.mu.Unlock()
		http.Error(w, "too many pending sessions", http.StatusTooManyRequests)
		return
	}
	expires := now.Add(appChallengeTTL)
	s.challenges[challenge] = expires
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "expires_at": expires.Unix()})
}

type openSessionRequest struct {
	Challenge   string `json:"challenge"`
	ClientNonce string `json:"client_nonce"`
	Proof       string `json:"proof"`
}

func (s *Server) openSession(w http.ResponseWriter, r *http.Request, origin string) {
	defer r.Body.Close()
	var input openSessionRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || !validNonce(input.ClientNonce, 16) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := s.now()
	s.mu.Lock()
	expires, issued := s.challenges[input.Challenge]
	delete(s.challenges, input.Challenge)
	appKey := s.appKey
	s.mu.Unlock()
	if !issued || !now.Before(expires) ||
		!equalMAC(mac(appKey, appOpenLabel, origin, input.Challenge, input.ClientNonce), input.Proof) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessionExpires := now.Add(10 * time.Minute)
	s.mu.Lock()
	for key, value := range s.sessions {
		if !now.Before(value.expires) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 64 {
		s.mu.Unlock()
		http.Error(w, "too many sessions", http.StatusTooManyRequests)
		return
	}
	expiresAt := sessionExpires.Unix()
	s.sessions[token] = session{
		csrf: csrf, expires: sessionExpires, nonces: make(map[string]time.Time),
		key:    appSessionKey(appKey, origin, input.Challenge, input.ClientNonce, token, csrf, expiresAt),
		origin: origin, sealed: make(map[string]struct{}),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"session":     token,
		"csrf":        csrf,
		"expires_at":  expiresAt,
		"owner_proof": macB64(appKey, appOwnerLabel, origin, input.Challenge, input.ClientNonce, token, csrf, strconv.FormatInt(expiresAt, 10)),
	})
}

// refreshSecret reloads the local secret so `dragpass-keeper app
// rotate-secret` takes effect in a running owner: a changed secret drops every
// App session and pending challenge, and the old pairing key opens nothing.
func (s *Server) refreshSecret() error {
	s.mu.Lock()
	current := s.secret
	s.mu.Unlock()
	latest, err := current.Reload()
	if err != nil {
		return err
	}
	if latest.Equal(current) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secret = latest
	s.appKey = latest.AppPairingKey()
	s.sessions = make(map[string]session)
	s.challenges = make(map[string]time.Time)
	s.proxy.rekey(latest.NativeProxyKey())
	return nil
}

func constantTimeEqual(provided, expected string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *Server) closeSession(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) signRequest(w http.ResponseWriter, r *http.Request) {
	request, ok := s.openAppRequest(w, r)
	if !ok {
		return
	}
	var input requestSignature
	decoder := json.NewDecoder(bytes.NewReader(request.plain))
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := validateRequestSignature(input, s.now()); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	token := request.token
	s.mu.Lock()
	current, ok := s.sessions[token]
	if !ok || !s.now().Before(current.expires) {
		delete(s.sessions, token)
		s.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if _, replay := current.nonces[input.Nonce]; replay {
		s.mu.Unlock()
		http.Error(w, "replayed request", http.StatusConflict)
		return
	}
	if len(current.nonces) >= maxSessionNonces {
		s.mu.Unlock()
		http.Error(w, "session request limit reached", http.StatusTooManyRequests)
		return
	}
	current.nonces[input.Nonce] = s.now()
	for nonce, seen := range current.nonces {
		if s.now().Sub(seen) > 2*time.Minute {
			delete(current.nonces, nonce)
		}
	}
	s.sessions[token] = current
	s.mu.Unlock()
	canonical := strings.Join([]string{
		"dp-req-v1", input.Method, input.Path, input.Query, input.Timestamp,
		input.Nonce, input.BodySHA256, input.AccountID, input.TokenID, input.DeviceID,
	}, "\n")
	body, _ := json.Marshal(map[string]string{"canonical_request": canonical})
	response, err := s.handle("sign_request", body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.writeSealed(w, request, response)
}

func validateRequestSignature(input requestSignature, now time.Time) error {
	method := strings.ToUpper(input.Method)
	if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
		return errors.New("invalid method")
	}
	if input.Method != method || !strings.HasPrefix(input.Path, "/api/v1/") || strings.ContainsAny(input.Path, "?#%\\\r\n") || path.Clean(input.Path) != input.Path {
		return errors.New("invalid path")
	}
	query, err := url.ParseQuery(input.Query)
	if err != nil || query.Encode() != input.Query {
		return errors.New("invalid canonical query")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(input.Nonce)
	if err != nil || len(nonce) < 16 || len(input.Nonce) > 128 {
		return errors.New("invalid query or nonce")
	}
	if _, err := hex.DecodeString(input.BodySHA256); err != nil || len(input.BodySHA256) != sha256.Size*2 || input.BodySHA256 != strings.ToLower(input.BodySHA256) {
		return errors.New("invalid body hash")
	}
	if !validUUID(input.AccountID) {
		return errors.New("invalid account id")
	}
	if !validUUID(input.TokenID) {
		return errors.New("invalid token id")
	}
	if len(input.DeviceID) < 8 || len(input.DeviceID) > 128 || strings.ContainsAny(input.DeviceID, "\r\n") {
		return errors.New("invalid device id")
	}
	seconds, err := strconv.ParseInt(input.Timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != input.Timestamp {
		return errors.New("invalid timestamp")
	}
	if delta := now.Unix() - seconds; delta < -60 || delta > 60 {
		return errors.New("stale timestamp")
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validUUID(value string) bool {
	return value == strings.ToLower(value) && uuidPattern.MatchString(value)
}

func (s *Server) handle(action string, payload []byte) (proto.BaseResponse, error) {
	request := map[string]any{"action": action}
	if len(payload) > 0 {
		var decoded any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			return proto.BaseResponse{}, err
		}
		request["payload"] = decoded
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return proto.BaseResponse{}, err
	}
	return s.app.HandleRequest(encoded), nil
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isAppFetch(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "same-site" || site == "cross-site"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
