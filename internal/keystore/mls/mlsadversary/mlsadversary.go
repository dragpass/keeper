// Package mlsadversary drives mls/examples/adversary.rs, a test-only MLS
// client built on mls-rs with its permissive DefaultMlsRules, so a test can
// hand a normal Keeper Commits that are cryptographically valid, signed by a
// real member, and forbidden by product policy.
//
// It is imported only by tests. The client plays one existing device: it is
// given that device's leaf signature key and declaration, so its KeyPackage
// passes every leaf check an honest one would, and whatever it is refused for
// is the rule under test.
package mlsadversary

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// BinaryEnv names a prebuilt adversary binary. Unset, the first Start builds
// it with cargo from the module's mls crate.
const BinaryEnv = "DRAGPASS_MLS_ADVERSARY"

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary is the adversary executable, built once per test process.
func binary() (string, error) {
	buildOnce.Do(func() {
		if p := os.Getenv(BinaryEnv); p != "" {
			binPath = p
			return
		}
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}
		manifest := filepath.Join(root, "mls", "Cargo.toml")
		cmd := exec.Command("cargo", "build", "--release", "--locked", "--example", "adversary",
			"--manifest-path", manifest)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("cargo build --example adversary: %v\n%s", err, out)
			return
		}
		name := "adversary"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		binPath = filepath.Join(root, "mls", "target", "release", "examples", name)
	})
	return binPath, buildErr
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("mlsadversary: no go.mod above the working directory")
		}
		dir = parent
	}
}

// Client is one running adversary process.
type Client struct {
	t   testing.TB
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

// Start runs the adversary as the device whose leaf key record is leaf.
// roles says whether its leaves advertise the room roles extension, as every
// Keeper since wave 5 does; false plays a Keeper from before it.
func Start(t testing.TB, leaf keychain.MLSLeafKey, roles bool) *Client {
	t.Helper()
	path, err := binary()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &Client{t: t, cmd: cmd, in: in, out: bufio.NewReaderSize(stdout, 1<<20)}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	identity := "dragpass.mls.credential|1|" + leaf.AccountID + "|" + leaf.DeviceID
	flag := "0"
	if roles {
		flag = "1"
	}
	lifetime := strconv.FormatInt(int64(time.Hour/time.Second), 10)
	c.do("identity", hex.EncodeToString([]byte(identity)), hex.EncodeToString(leaf.SecretKey),
		hex.EncodeToString(leaf.PublicKey), hexOr(leaf.Declaration), lifetime, flag)
	return c
}

func hexOr(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func (c *Client) do(fields ...string) []string {
	c.t.Helper()
	if _, err := io.WriteString(c.in, strings.Join(fields, " ")+"\n"); err != nil {
		c.t.Fatalf("adversary %s: %v", fields[0], err)
	}
	line, err := c.out.ReadString('\n')
	if err != nil {
		c.t.Fatalf("adversary %s: no answer: %v", fields[0], err)
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 0 || parts[0] != "ok" {
		c.t.Fatalf("adversary %s: %s", fields[0], strings.TrimSpace(line))
	}
	return parts[1:]
}

func (c *Client) unhex(s string) []byte {
	c.t.Helper()
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

// KeyPackage is one KeyPackage message; its private keys stay in the
// adversary for the join.
func (c *Client) KeyPackage() []byte {
	c.t.Helper()
	return c.unhex(c.do("key-package")[0])
}

// KeyPackageEntry is one KeyPackage framed as a Keeper pool entry, with its
// reference and not_after, for a test that puts it in a pool.
func (c *Client) KeyPackageEntry() (entry, ref []byte, notAfter uint64) {
	c.t.Helper()
	f := c.do("key-package-entry")
	n, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil {
		c.t.Fatal(err)
	}
	return c.unhex(f[0]), c.unhex(f[1]), n
}

// Create makes a group of the adversary's own with the roles payload given
// (nil for none), at epoch 0.
func (c *Client) Create(groupID, roles []byte) {
	c.t.Helper()
	c.do("create", hex.EncodeToString(groupID), hexOr(roles))
}

// Join joins from a Welcome and reports the epoch.
func (c *Client) Join(welcome []byte) uint64 {
	c.t.Helper()
	return c.epochOf(c.do("join", hex.EncodeToString(welcome)))
}

// Process applies someone else's message, keeping the adversary in step.
func (c *Client) Process(message []byte) uint64 {
	c.t.Helper()
	return c.epochOf(c.do("process", hex.EncodeToString(message)))
}

func (c *Client) epochOf(f []string) uint64 {
	c.t.Helper()
	n, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		c.t.Fatal(err)
	}
	return n
}

// Commit is what one Commit carries. Nothing about it is judged.
type Commit struct {
	Adds    [][]byte
	Removes []uint32
	Roles   []byte
	AAD     []byte
	// Apply moves the adversary to the Commit's epoch; otherwise it stays.
	Apply bool
}

// Build builds the Commit and returns it and its Welcome (nil with no Add).
func (c *Client) Build(m Commit) (commit, welcome []byte) {
	c.t.Helper()
	adds := make([]string, len(m.Adds))
	for i, kp := range m.Adds {
		adds[i] = hex.EncodeToString(kp)
	}
	removes := make([]string, len(m.Removes))
	for i, r := range m.Removes {
		removes[i] = strconv.FormatUint(uint64(r), 10)
	}
	apply := "0"
	if m.Apply {
		apply = "1"
	}
	f := c.do("commit", joinOr(adds), joinOr(removes), hexOr(m.Roles), hexOr(m.AAD), apply)
	return c.unhex(f[0]), c.unhex(f[1])
}

func joinOr(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ",")
}

// IndexOf is the leaf index of account's device in the adversary's tree.
func (c *Client) IndexOf(account, device string) uint32 {
	c.t.Helper()
	want := hex.EncodeToString([]byte("dragpass.mls.credential|1|" + account + "|" + device))
	for _, m := range strings.Split(c.do("roster")[0], ",") {
		index, identity, ok := strings.Cut(m, ":")
		if ok && identity == want {
			n, err := strconv.ParseUint(index, 10, 32)
			if err != nil {
				c.t.Fatal(err)
			}
			return uint32(n)
		}
	}
	c.t.Fatalf("adversary tree holds no leaf of %s/%s", account, device)
	return 0
}
