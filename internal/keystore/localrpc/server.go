package localrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/version"
)

const maxRequestBytes = 8 * 1024
const maxSessionNonces = 4096
const maxNativeMessageBytes = dispatch.MaxMessageSize
const nativeProxyProtocolVersion = 1

const DefaultAddress = "127.0.0.1:47623"
const NativeExtensionOrigin = "chrome-extension://cmgjlocmnppfpknaipdfodjhbplnhimk"

type Server struct {
	app      *keystore.App
	origins  map[string]struct{}
	host     string
	now      func() time.Time
	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	csrf    string
	expires time.Time
	nonces  map[string]time.Time
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

func New(app *keystore.App, origins []string) (*Server, error) {
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
	return &Server{app: app, origins: allowed, now: time.Now, sessions: make(map[string]session)}, nil
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
		maxBytes := int64(maxRequestBytes)
		if r.URL.Path == "/v1/native-proxy/message" {
			maxBytes = int64(maxNativeMessageBytes)
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
		writeJSON(w, http.StatusOK, map[string]any{
			"version": version.Version,
			"hash":    version.BinaryHash,
		})
	case origin == NativeExtensionOrigin && r.Method == http.MethodGet && r.URL.Path == "/v1/native-proxy/health":
		writeJSON(w, http.StatusOK, map[string]any{
			"version":          version.Version,
			"hash":             version.BinaryHash,
			"protocol_version": nativeProxyProtocolVersion,
		})
	case origin == NativeExtensionOrigin && r.Method == http.MethodPost && r.URL.Path == "/v1/native-proxy/message":
		defer r.Body.Close()
		request, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		response, err := json.Marshal(s.app.HandleRequest(request))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
		s.openSession(w)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/session":
		s.closeSession(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
		if !s.authorized(w, r) {
			return
		}
		s.dispatch(w, "request_key_status", nil)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/request-signature":
		if !s.authorized(w, r) {
			return
		}
		s.signRequest(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/sign-alias":
		s.dispatchAppAuthAction(w, r, proto.ActionSignAliasWithTimestamp, func() any {
			return &proto.SignAliasWithTimestampRequest{}
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/login/sign-challenge":
		s.dispatchAppAuthAction(w, r, proto.ActionSignChallengeToken, func() any {
			return &proto.SignChallengeTokenRequest{}
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
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/signup/save-session-code":
		s.dispatchAppAuthActionWithoutResult(w, r, proto.ActionSaveSessionCode, func() any {
			return &proto.SaveSessionCodeRequest{}
		})
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
	if !s.authorized(w, r) {
		return
	}
	s.mu.Lock()
	current := s.sessions[bearerToken(r)]
	validCSRF := r.Header.Get("X-DragPass-CSRF") == current.csrf
	s.mu.Unlock()
	if !validCSRF {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	input := newPayload()
	decoder := json.NewDecoder(r.Body)
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
	request := map[string]any{"action": action}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	request["payload"] = decoded
	encoded, err := json.Marshal(request)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response := s.app.HandleRequest(encoded)
	if suppressResult && response.Success {
		response.Data = map[string]bool{"stored": true}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) openSession(w http.ResponseWriter) {
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
	expires := s.now().Add(10 * time.Minute)
	s.mu.Lock()
	for key, value := range s.sessions {
		if !s.now().Before(value.expires) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 64 {
		s.mu.Unlock()
		http.Error(w, "too many sessions", http.StatusTooManyRequests)
		return
	}
	s.sessions[token] = session{csrf: csrf, expires: expires, nonces: make(map[string]time.Time)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"session": token, "csrf": csrf, "expires_at": expires.Unix()})
}

func (s *Server) closeSession(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	token := bearerToken(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[token]
	if !ok || !s.now().Before(current.expires) {
		delete(s.sessions, token)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	s.sessions[token] = current
	return true
}

func (s *Server) signRequest(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	s.mu.Lock()
	current, ok := s.sessions[token]
	if !ok || !s.now().Before(current.expires) {
		delete(s.sessions, token)
		s.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-DragPass-CSRF") != current.csrf {
		s.mu.Unlock()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.mu.Unlock()
	defer r.Body.Close()
	var input requestSignature
	decoder := json.NewDecoder(r.Body)
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
	s.mu.Lock()
	current, ok = s.sessions[token]
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
	s.dispatch(w, "sign_request", body)
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

func (s *Server) dispatch(w http.ResponseWriter, action string, payload []byte) {
	request := map[string]any{"action": action}
	if len(payload) > 0 {
		var decoded any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		request["payload"] = decoded
	}
	encoded, _ := json.Marshal(request)
	response, err := json.Marshal(s.app.HandleRequest(encoded))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
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
