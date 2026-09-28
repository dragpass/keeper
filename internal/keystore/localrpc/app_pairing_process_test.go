package localrpc

import (
	"bytes"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

// reservedAddress is a free port in 47651-47659, the range these tests may
// take, so an isolated Keeper never lands on one another stack is using.
func reservedAddress(t *testing.T) string {
	t.Helper()
	for port := 47651; port <= 47659; port++ {
		address := "127.0.0.1:" + strconv.Itoa(port)
		listener, err := net.Listen("tcp4", address)
		if err == nil {
			listener.Close()
			return address
		}
	}
	t.Fatal("no free port in 47651-47659")
	return ""
}

// The whole App path against the release binary, the one CI runs on Windows
// too: `dragpass-keeper app pair --no-open` prints the link, the App takes
// the pairing key from its fragment only, opens a session against the running
// App service, proves the owner, and round-trips sealed requests, a chat
// runtime claim and a lease-gated chat action among them.
func TestAppPairsFromThePrintedLinkAndRoundTripsSealedRequests(t *testing.T) {
	dir, address := t.TempDir(), reservedAddress(t)
	owner := startAppService(t, dir, address)

	pair := exec.Command(builtKeeper(t), "app", "pair", "--no-open")
	pair.Env = []string{
		localsecret.DirEnvVar + "=" + filepath.Join(dir, "local"),
		"HOME=" + filepath.Join(dir, "home"),
		"PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"USERPROFILE=" + filepath.Join(dir, "home"),
	}
	var printed bytes.Buffer
	pair.Stdout, pair.Stderr = &printed, &printed
	if err := pair.Run(); err != nil {
		t.Fatalf("app pair: %v\n%s", err, printed.String())
	}
	const marker = testOrigin + "/#keeper-pair="
	at := strings.Index(printed.String(), marker)
	if at < 0 {
		t.Fatalf("app pair printed no link:\n%s", printed.String())
	}
	encoded := strings.Fields(printed.String()[at+len(marker):])[0]
	pairingKey, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(pairingKey) == 0 {
		t.Fatalf("pairing key in the link: %v", err)
	}

	client := &testAppClient{address: address, origin: testOrigin, pairingKey: pairingKey}
	if err := client.open(); err != nil {
		t.Fatalf("open session with the printed pairing key: %v\n%s", err, owner.stderr.String())
	}
	if status, err := client.status(); err != nil || !status.Success {
		t.Fatalf("sealed status: %+v %v", status, err)
	}
	if claim, err := client.claim(routeHolder); err != nil || !claim.Success || client.epoch == "" {
		t.Fatalf("sealed claim: %+v %v", claim, err)
	}
	if ran, err := client.call("/v1/chat/mls_leaf_abort", map[string]any{}); err != nil || !leaseAdmitted(ran) {
		t.Fatalf("sealed gated call with the lease: %+v %v", ran, err)
	}

	// A key that is not the one the owner holds opens nothing.
	wrong := &testAppClient{address: address, origin: testOrigin, pairingKey: bytes.Repeat([]byte{7}, len(pairingKey))}
	if err := wrong.open(); err == nil {
		t.Fatal("a session opened with a pairing key the owner does not hold")
	}
}
