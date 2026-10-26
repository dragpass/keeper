package localrpc

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// hangUpAfterRequest closes the proven owner and puts a listener on its address
// that reads one whole request and closes the connection without answering:
// what the proxy sees when the owner dies while it runs a request.
func hangUpAfterRequest(t *testing.T, address string, closeOwner func()) <-chan struct{} {
	t.Helper()
	closeOwner()
	var listener net.Listener
	var err error
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if listener, err = net.Listen("tcp4", address); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("listen on the owner address: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if request, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			_ = request.Body.Close()
			received <- struct{}{}
		}
		_ = conn.Close()
	}()
	return received
}

func TestNativeMessagingProxyReportsAnUnansweredRequestAsOutcomeUnknown(t *testing.T) {
	secret := testSecret(t)
	server := newTestServerWithSecret(t, secret)
	address, closeOwner := startClosableTestOwner(t, server)
	_, _, proxy, err := acquireNativeOwnerAt(address, secret.NativeProxyKey(), time.Second)
	if err != nil || proxy == nil {
		t.Fatalf("acquire: %v", err)
	}
	received := hangUpAfterRequest(t, address, closeOwner)

	_, err = proxy.Forward([]byte(`{"action":"credential_http_request","request_id":"r-1"}`))
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the owner address")
	}
	if !errors.Is(err, ErrOwnerOutcomeUnknown) {
		t.Fatalf("an owner that took the request and went away: err=%v, want ErrOwnerOutcomeUnknown", err)
	}
}

func TestNativeMessagingProxyDoesNotReportAnUnsentRequestAsOutcomeUnknown(t *testing.T) {
	secret := testSecret(t)
	server := newTestServerWithSecret(t, secret)
	address, closeOwner := startClosableTestOwner(t, server)
	_, _, proxy, err := acquireNativeOwnerAt(address, secret.NativeProxyKey(), time.Second)
	if err != nil || proxy == nil {
		t.Fatalf("acquire: %v", err)
	}
	// Nobody listens any more: the request cannot have been sent.
	closeOwner()

	_, err = proxy.Forward([]byte(`{"action":"credential_http_request","request_id":"r-2"}`))
	if err == nil || errors.Is(err, ErrOwnerOutcomeUnknown) {
		t.Fatalf("a refused connection: err=%v, want an error other than ErrOwnerOutcomeUnknown", err)
	}
}

// startClosableTestOwner is startTestOwner with a way to stop the owner
// in the middle of a test.
func startClosableTestOwner(t *testing.T, server *Server) (string, func()) {
	t.Helper()
	server.now = time.Now
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.host = listener.Addr().String()
	httpServer := &http.Server{Handler: server.Handler()}
	go func() { _ = httpServer.Serve(listener) }()
	closed := false
	closeOwner := func() {
		if !closed {
			closed = true
			_ = httpServer.Close()
		}
	}
	t.Cleanup(closeOwner)
	return server.host, closeOwner
}
