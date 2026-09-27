package localrpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A chat answer slower than the default write deadline is still delivered,
// while every other route keeps the default. The deadlines are shortened so
// the test runs in well under a second per case.
func TestChatRoutesGetTheLongWriteDeadline(t *testing.T) {
	server := newTestServer(t)
	server.now = time.Now
	server.writeTimeout = 150 * time.Millisecond
	server.longWriteTimeout = 3 * time.Second
	address := freeLoopbackAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listening := make(chan struct{})
	go func() {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Error(err)
			close(listening)
			return
		}
		close(listening)
		_ = server.ServeListener(ctx, listener)
	}()
	<-listening
	server.onAction = func(string, []byte, proto.BaseResponse) { time.Sleep(400 * time.Millisecond) }

	client := &testAppClient{address: address, origin: testOrigin, pairingKey: server.appKey}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := client.open(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("open session: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, path := range []string{"/v1/chat/capability", "/v1/chat/mls_leaf_status", "/v1/peer-key/chain-evaluate"} {
		body := map[string]any{}
		if path == "/v1/peer-key/chain-evaluate" {
			body = map[string]any{"owner_account_id": routeOwner, "account_id": routePeer, "public_key": routeKeypair(t).PublicKey}
		}
		if _, err := client.call(path, body); err != nil {
			t.Fatalf("%s slower than the default deadline was cut off: %v", path, err)
		}
	}
	if _, err := client.call("/v1/status", map[string]string{}); err == nil {
		t.Fatal("a non-chat route outlived the default write deadline")
	}
}
