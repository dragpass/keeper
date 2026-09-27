package localrpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

// These run the release entry point (`dragpass-keeper --app-service`) as a
// real process on an isolated loopback port, then take the port over in the
// middle of an App session, as another OS user could once the owner exits.

var (
	keeperBuildOnce sync.Once
	keeperBinary    string
	keeperBuildErr  error
	keeperBuildDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if keeperBuildDir != "" {
		os.RemoveAll(keeperBuildDir)
	}
	os.Exit(code)
}

func builtKeeper(t *testing.T) string {
	t.Helper()
	keeperBuildOnce.Do(func() {
		keeperBuildDir, keeperBuildErr = os.MkdirTemp("", "keeper-localrpc-process-")
		if keeperBuildErr != nil {
			return
		}
		name := "dragpass-keeper"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		keeperBinary = filepath.Join(keeperBuildDir, name)
		build := exec.Command("go", "build", "-o", keeperBinary, ".")
		build.Dir = filepath.Join("..", "..", "..")
		if out, err := build.CombinedOutput(); err != nil {
			keeperBuildErr = fmt.Errorf("build the keeper: %v\n%s", err, out)
		}
	})
	if keeperBuildErr != nil {
		t.Fatal(keeperBuildErr)
	}
	return keeperBinary
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

type keeperProcess struct {
	cmd     *exec.Cmd
	stderr  *bytes.Buffer
	exited  chan struct{}
	waitErr error
}

// startAppService runs one isolated Keeper owner. dir holds its local secret
// and home; nothing reaches the developer's Keychain or secret directory.
func startAppService(t *testing.T, dir, address string) *keeperProcess {
	t.Helper()
	cmd := exec.Command(builtKeeper(t), "--app-service")
	cmd.Env = []string{
		"KEEPER_E2E_MODE=1",
		localsecret.DirEnvVar + "=" + filepath.Join(dir, "local"),
		AddressEnvVar + "=" + address,
		"HOME=" + filepath.Join(dir, "home"),
		"PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"USERPROFILE=" + filepath.Join(dir, "home"),
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &keeperProcess{cmd: cmd, stderr: stderr, exited: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exited) }()
	t.Cleanup(p.kill)
	client := &testAppClient{address: address, origin: testOrigin}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if response, err := client.do(http.MethodGet, "/v1/health", nil, false); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return p
			}
		}
		select {
		case <-p.exited:
			t.Fatalf("keeper exited before serving: %v\n%s", p.waitErr, stderr.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("keeper did not serve %s\n%s", address, stderr.String())
	return nil
}

func (p *keeperProcess) kill() {
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
	}
}

func pairingKeyOf(t *testing.T, dir string) []byte {
	t.Helper()
	t.Setenv(localsecret.DirEnvVar, filepath.Join(dir, "local"))
	secret, err := localsecret.Load()
	if err != nil {
		t.Fatal(err)
	}
	return secret.AppPairingKey()
}

// squatter takes a freed port and answers every request the way the owner
// used to, recording what it was sent.
type squatter struct {
	mu     sync.Mutex
	bodies []string
	server *http.Server
}

func takeOverAddress(t *testing.T, address string) *squatter {
	t.Helper()
	var listener net.Listener
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		if listener, err = net.Listen("tcp4", address); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("take over %s: %v", address, err)
	}
	s := &squatter{}
	s.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":{"stored":true,"has_active":true,"signature":"forged","timestamp":1}}`)
	})}
	go func() { _ = s.server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	})
	return s
}

func (s *squatter) seen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.bodies, "\n")
}

const swapPasswordMarker = "correct-horse-battery-staple-7f3a"

func TestAppSessionRefusesAnOwnerThatTookThePortMidSession(t *testing.T) {
	dir, address := t.TempDir(), freeLoopbackAddress(t)
	owner := startAppService(t, dir, address)
	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, dir)}
	if err := client.open(); err != nil {
		t.Fatalf("open session with the real owner: %v\n%s", err, owner.stderr.String())
	}
	if response, err := client.status(); err != nil || !response.Success {
		t.Fatalf("status through the real owner: %+v, %v", response, err)
	}

	owner.kill()
	squat := takeOverAddress(t, address)

	response, err := client.call("/v1/auth/login/restore-device-master", map[string]string{
		"password":          swapPasswordMarker,
		"encrypted_dek_b64": "c2VhbGVkLWRlaw",
	})
	seen := squat.seen()
	if seen == "" {
		t.Fatal("the request never reached the port; the test proves nothing")
	}
	if err == nil {
		t.Errorf("the App accepted an answer from the process that took the port: %+v", response)
	}
	if strings.Contains(seen, swapPasswordMarker) {
		t.Errorf("the process that took the port read the password:\n%s", seen)
	}
}

func TestAppSessionFailsAgainstAnotherUsersKeeperMidSession(t *testing.T) {
	address := freeLoopbackAddress(t)
	victimDir, otherDir := t.TempDir(), t.TempDir()
	victim := startAppService(t, victimDir, address)
	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKeyOf(t, victimDir)}
	if err := client.open(); err != nil {
		t.Fatalf("open session with the victim's owner: %v\n%s", err, victim.stderr.String())
	}
	victim.kill()
	startAppService(t, otherDir, address)

	if response, err := client.status(); err == nil {
		t.Fatalf("a request succeeded against another user's Keeper: %+v", response)
	}
	if err := client.open(); err == nil {
		t.Fatal("the App opened a session with another user's Keeper")
	}
}
