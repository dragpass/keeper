package localrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const nativeProxyTimeout = 10 * time.Second
const nativeOwnerWait = 5 * time.Second

// NativeRole is what a Chrome-launched Keeper does after looking at the
// shared loopback address.
type NativeRole int

const (
	// RoleOwner holds the address and serves the App and other hosts.
	RoleOwner NativeRole = iota
	// RoleProxy forwards its Native Messaging traffic to a proven owner.
	RoleProxy
	// RoleStandalone serves its own stdio only. Chosen when the address is held
	// by something that cannot prove the local secret (another OS user's
	// Keeper, an older protocol, a port squatter): nothing is sent to it.
	RoleStandalone
)

var errOwnerUnproven = errors.New("local listener did not prove the Keeper local secret")

func AcquireNativeOwner(address string, secret localsecret.Secret) (NativeRole, net.Listener, *NativeProxy, error) {
	return acquireNativeOwnerAt(address, secret.NativeProxyKey(), nativeOwnerWait)
}

func AcquireAppServiceOwner(ctx context.Context, address string) (net.Listener, error) {
	return acquireAppServiceOwnerAt(ctx, address, 30*time.Second)
}

func acquireAppServiceOwnerAt(ctx context.Context, address string, wait time.Duration) (net.Listener, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		listener, err := net.Listen("tcp4", address)
		if err == nil {
			return listener, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("timed out waiting for the Native Messaging Keeper owner")
		case <-ticker.C:
		}
	}
}

func acquireNativeOwnerAt(address string, proxyKey []byte, wait time.Duration) (NativeRole, net.Listener, *NativeProxy, error) {
	listener, err := net.Listen("tcp4", address)
	if err == nil {
		return RoleOwner, listener, nil, nil
	}
	proxy := &NativeProxy{address: address, key: proxyKey, now: time.Now}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		probeErr := proxy.prove()
		if probeErr == nil {
			return RoleProxy, nil, proxy, nil
		}
		if errors.Is(probeErr, errOwnerUnproven) {
			return RoleStandalone, nil, nil, nil
		}
		if errors.Is(probeErr, syscall.ECONNREFUSED) {
			if listener, err := net.Listen("tcp4", address); err == nil {
				return RoleOwner, listener, nil, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return RoleStandalone, nil, nil, nil
}

// NativeProxy forwards Native Messaging requests to one proven owner
// instance over the sealed channel.
type NativeProxy struct {
	address  string
	key      []byte
	instance string
	now      func() time.Time
}

// prove runs the health challenge and records the owner instance the sealed
// requests are addressed to.
func (p *NativeProxy) prove() error {
	challengeBytes := make([]byte, 16)
	if _, err := rand.Read(challengeBytes); err != nil {
		return err
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request, err := nativeProxyRequest(ctx, p.address, http.MethodGet, "/v1/native-proxy/health?challenge="+challenge, nil)
	if err != nil {
		return err
	}
	response, err := nativeProxyClient(500 * time.Millisecond).Do(request)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return syscall.ECONNREFUSED
		}
		return errors.New("local Keeper owner did not answer its health check")
	}
	defer response.Body.Close()
	var health struct {
		ProtocolVersion int    `json:"protocol_version"`
		Instance        string `json:"instance"`
		Proof           string `json:"proof"`
	}
	if response.StatusCode != http.StatusOK ||
		json.NewDecoder(io.LimitReader(response.Body, 2048)).Decode(&health) != nil ||
		health.ProtocolVersion != nativeProxyProtocolVersion || health.Instance == "" ||
		!equalMAC(healthProof(p.key, challenge, health.Instance), health.Proof) {
		return errOwnerUnproven
	}
	p.instance = health.Instance
	return nil
}

// Forward sends one request. A 409 means the owner restarted and refused the
// request before running it, so re-proving and retrying once is safe.
func (p *NativeProxy) Forward(message []byte) (proto.BaseResponse, error) {
	if len(message) == 0 || len(message) > int(dispatch.MaxMessageSize) {
		return proto.BaseResponse{}, errors.New("native message size is invalid")
	}
	result, err := p.forwardOnce(message)
	if errors.Is(err, errStaleProxyInstance) {
		if proveErr := p.prove(); proveErr != nil {
			return proto.BaseResponse{}, errors.New("local Keeper owner could not be proven again")
		}
		result, err = p.forwardOnce(message)
	}
	return result, err
}

func (p *NativeProxy) forwardOnce(message []byte) (proto.BaseResponse, error) {
	sealed, requestNonce, err := sealProxyRequest(p.key, p.instance, p.now(), message)
	if err != nil {
		return proto.BaseResponse{}, errors.New("native message could not be sealed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeProxyTimeout)
	defer cancel()
	request, err := nativeProxyRequest(ctx, p.address, http.MethodPost, "/v1/native-proxy/message", bytes.NewReader(sealed))
	if err != nil {
		return proto.BaseResponse{}, errors.New("native message could not be prepared")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := nativeProxyClient(nativeProxyTimeout).Do(request)
	if err != nil {
		return proto.BaseResponse{}, errors.New("local Keeper owner did not complete the request")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		return proto.BaseResponse{}, errStaleProxyInstance
	}
	if response.StatusCode != http.StatusOK {
		return proto.BaseResponse{}, fmt.Errorf("local Keeper owner rejected the request (%d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, sealedLimit()+1))
	if err != nil || int64(len(body)) > sealedLimit() {
		return proto.BaseResponse{}, errors.New("local Keeper owner returned an invalid response")
	}
	plain, err := openProxyResponse(p.key, p.instance, requestNonce, body)
	if err != nil {
		return proto.BaseResponse{}, errors.New("local Keeper owner returned an unauthenticated response")
	}
	var result proto.BaseResponse
	if err := json.Unmarshal(plain, &result); err != nil {
		return proto.BaseResponse{}, errors.New("local Keeper owner returned malformed response data")
	}
	return result, nil
}

// sealedLimit bounds a sealed envelope: base64 growth plus JSON framing.
func sealedLimit() int64 {
	return int64(dispatch.MaxMessageSize)*4/3 + 1024
}

func nativeProxyRequest(ctx context.Context, address, method, path string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, body)
	if err != nil {
		return nil, err
	}
	request.Host = address
	request.Header.Set("Origin", NativeExtensionOrigin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("X-DragPass-Local-RPC", "1")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	return request, nil
}

func nativeProxyClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
