package localrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// nativeHost is a Chrome-launched Keeper speaking Native Messaging on stdio.
type nativeHost struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *bytes.Buffer
}

func startNativeHost(t *testing.T, dir, address string) *nativeHost {
	t.Helper()
	cmd := exec.Command(builtKeeper(t))
	cmd.Env = []string{
		"KEEPER_E2E_MODE=1",
		localsecret.DirEnvVar + "=" + filepath.Join(dir, "local"),
		AddressEnvVar + "=" + address,
		"HOME=" + filepath.Join(dir, "home"),
		"PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"USERPROFILE=" + filepath.Join(dir, "home"),
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	host := &nativeHost{cmd: cmd, stdin: stdin, stdout: stdout, stderr: &bytes.Buffer{}}
	cmd.Stderr = host.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return host
}

func (h *nativeHost) send(t *testing.T, frame string) proto.BaseResponse {
	t.Helper()
	if err := binary.Write(h.stdin, binary.LittleEndian, uint32(len(frame))); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(h.stdin, frame); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		response proto.BaseResponse
		err      error
	}
	answered := make(chan answer, 1)
	go func() {
		var length uint32
		if err := binary.Read(h.stdout, binary.LittleEndian, &length); err != nil {
			answered <- answer{err: err}
			return
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(h.stdout, body); err != nil {
			answered <- answer{err: err}
			return
		}
		var response proto.BaseResponse
		answered <- answer{response: response, err: json.Unmarshal(body, &response)}
	}()
	select {
	case got := <-answered:
		if got.err != nil {
			t.Fatalf("native host answer: %v\n%s", got.err, h.stderr.String())
		}
		return got.response
	case <-time.After(15 * time.Second):
		t.Fatalf("native host did not answer\n%s", h.stderr.String())
	}
	return proto.BaseResponse{}
}

// leaseAdmitted reports that the lease let the action through to its handler.
// In e2e mode the mock keyring answers mls_leaf_abort with a storage failure
// when nothing is pending, which is the handler running, not the gate.
func leaseAdmitted(response proto.BaseResponse) bool {
	return response.ErrorCode != "chat_runtime_busy" && response.ErrorCode != "chat_runtime_lease_required"
}

// The real release binary as the App-service owner, a second real binary as
// the Native Messaging host that proxies to it, and an App session: while the
// App holds the chat runtime lease the Extension's gated frame is refused by
// the owner and runs nothing; once released it runs, and then keeps the App
// out for the Extension window.
func TestProxiedExtensionFrameIsRefusedWhileTheAppHoldsTheLease(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	owner := startAppService(t, dir, address)
	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	if err := client.open(); err != nil {
		t.Fatalf("open session: %v\n%s", err, owner.stderr.String())
	}
	host := startNativeHost(t, dir, address)
	if ping := host.send(t, `{"action":"ping","request_id":"p"}`); !ping.Success {
		t.Fatalf("ping through the proxy: %+v\n%s", ping, host.stderr.String())
	}

	claim, err := client.call("/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder})
	if err != nil || !claim.Success {
		t.Fatalf("claim: %+v %v\n%s", claim, err, owner.stderr.String())
	}
	refused := host.send(t, `{"action":"mls_leaf_abort","request_id":"g","payload":{}}`)
	if refused.Success || refused.ErrorCode != "chat_runtime_busy" || refused.RequestID != "g" {
		t.Fatalf("proxied gated frame while the App holds the lease: %+v", refused)
	}
	if ran, err := client.call("/v1/chat/mls_leaf_abort", map[string]any{}); err != nil || !leaseAdmitted(ran) {
		t.Fatalf("the App's own gated call: %+v %v", ran, err)
	}

	if released, err := client.call("/v1/chat/runtime/release", map[string]string{"holder_id": routeHolder}); err != nil || !released.Success {
		t.Fatalf("release: %+v %v", released, err)
	}
	if ran := host.send(t, `{"action":"mls_leaf_abort","request_id":"h","payload":{}}`); !leaseAdmitted(ran) {
		t.Fatalf("proxied gated frame after release: %+v", ran)
	}
	busy, err := client.call("/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder})
	if err != nil || busy.Success || busy.ErrorCode != "chat_runtime_busy" {
		t.Fatalf("claim right after Extension activity: %+v %v", busy, err)
	}
}
