package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/dragpass/keeper/internal/keystore/dispatch"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const nativeProxyTimeout = 10 * time.Second
const nativeOwnerWait = 5 * time.Second

func AcquireNativeOwner() (net.Listener, bool, error) {
	return acquireNativeOwnerAt(DefaultAddress, nativeOwnerWait)
}

func AcquireAppServiceOwner(ctx context.Context) (net.Listener, error) {
	return acquireAppServiceOwnerAt(ctx, DefaultAddress, 30*time.Second)
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
		_, _ = probeNativeProxyAt(address)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("timed out waiting for the Native Messaging Keeper owner")
		case <-ticker.C:
		}
	}
}

func acquireNativeOwnerAt(address string, wait time.Duration) (net.Listener, bool, error) {
	listener, err := net.Listen("tcp4", address)
	if err == nil {
		return listener, false, nil
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		available, probeErr := probeNativeProxyAt(address)
		if available {
			return nil, true, nil
		}
		if probeErr == nil || errors.Is(probeErr, syscall.ECONNREFUSED) {
			if listener, err := net.Listen("tcp4", address); err == nil {
				return listener, false, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, false, errors.New("another Keeper process owns the local service address but did not become ready")
}

func probeNativeProxyAt(address string) (bool, error) {
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	conn, err := dialer.Dial("tcp4", address)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return false, nil
		}
		return false, errors.New("local Keeper owner could not be checked")
	}
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request, err := nativeProxyRequest(ctx, address, http.MethodGet, "/v1/native-proxy/health", nil)
	if err != nil {
		return false, errors.New("local Keeper owner request could not be prepared")
	}
	response, err := nativeProxyClient(500 * time.Millisecond).Do(request)
	if err != nil {
		return false, errors.New("local Keeper owner did not answer its health check")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, errors.New("local Keeper owner does not support Native Messaging proxying")
	}
	var health struct {
		Version         string `json:"version"`
		ProtocolVersion int    `json:"protocol_version"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&health); err != nil || health.Version == "" || health.ProtocolVersion != nativeProxyProtocolVersion {
		return false, errors.New("local Keeper owner returned invalid health metadata")
	}
	return true, nil
}

func ForwardNativeMessage(message []byte) (proto.BaseResponse, error) {
	return forwardNativeMessageTo(DefaultAddress, message)
}

func forwardNativeMessageTo(address string, message []byte) (proto.BaseResponse, error) {
	if len(message) == 0 || len(message) > int(dispatch.MaxMessageSize) {
		return proto.BaseResponse{}, errors.New("native message size is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeProxyTimeout)
	defer cancel()
	request, err := nativeProxyRequest(ctx, address, http.MethodPost, "/v1/native-proxy/message", bytes.NewReader(message))
	if err != nil {
		return proto.BaseResponse{}, errors.New("native message could not be prepared")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := nativeProxyClient(nativeProxyTimeout).Do(request)
	if err != nil {
		return proto.BaseResponse{}, errors.New("local Keeper owner did not complete the request")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return proto.BaseResponse{}, fmt.Errorf("local Keeper owner rejected the request (%d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(dispatch.MaxMessageSize)+1))
	if err != nil || len(body) > int(dispatch.MaxMessageSize) {
		return proto.BaseResponse{}, errors.New("local Keeper owner returned an invalid response")
	}
	var result proto.BaseResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return proto.BaseResponse{}, errors.New("local Keeper owner returned malformed response data")
	}
	return result, nil
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
