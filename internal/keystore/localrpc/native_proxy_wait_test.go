package localrpc

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A credential sink request may take as long as the sink allows (30 s HTTP,
// 60 s exec). Neither the proxy nor the owner may give up on it at the
// ordinary deadline. Scaled down: the ordinary waits here are 200 ms, the
// owner takes 500 ms, and the sink waits are 2 s.
func TestNativeMessagingProxyWaitsForACredentialSinkAsLongAsTheSink(t *testing.T) {
	prevBase, prevWaits := nativeProxyTimeout, nativeProxyActionWaits
	nativeProxyTimeout = 200 * time.Millisecond
	nativeProxyActionWaits = map[string]time.Duration{
		proto.ActionCredentialHTTPRequest: 2 * time.Second,
		proto.ActionCredentialExecRequest: 2 * time.Second,
	}
	t.Cleanup(func() { nativeProxyTimeout, nativeProxyActionWaits = prevBase, prevWaits })

	secret := testSecret(t)
	server := newTestServerWithSecret(t, secret)
	server.now = time.Now
	server.writeTimeout = 200 * time.Millisecond
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.host = listener.Addr().String()
	slowOwner := &http.Server{
		WriteTimeout: server.writeTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/native-proxy/message" {
				time.Sleep(500 * time.Millisecond)
			}
			server.Handler().ServeHTTP(w, r)
		}),
	}
	go func() { _ = slowOwner.Serve(listener) }()
	t.Cleanup(func() { _ = slowOwner.Close() })

	_, _, proxy, err := acquireNativeOwnerAt(server.host, secret.NativeProxyKey(), time.Second)
	if err != nil || proxy == nil {
		t.Fatalf("acquire: %v", err)
	}
	for _, action := range []string{proto.ActionCredentialHTTPRequest, proto.ActionCredentialExecRequest} {
		// The owner refuses the empty request quickly once it runs it; what
		// matters is that its answer comes back at all.
		if _, err := proxy.Forward([]byte(`{"action":"` + action + `","request_id":"w-1","payload":{}}`)); err != nil {
			t.Fatalf("%s through a slow owner: %v", action, err)
		}
	}
	// An ordinary request keeps the ordinary wait.
	if _, err := proxy.Forward([]byte(`{"action":"ping","request_id":"w-2"}`)); err == nil {
		t.Fatal("an ordinary request waited past its deadline")
	}
}
