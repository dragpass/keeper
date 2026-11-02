//go:build keeper_e2e

// A real Keeper process: tracked encrypts keep an existing value as "same",
// detect a new value as "changed", stay "same" across a DEK version, and the
// first token still decrypts to its original value. Values are compared as
// SHA-256 hashes from the Keeper's memory clipboard; nothing is printed.

package changetrackprocess

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	orgID   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	groupID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	entryID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lv83-keeper-roundtrip-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "dragpass-keeper-e2e")
	build := exec.Command("go", "build", "-tags", "keeper_e2e", "-o", binaryPath, ".")
	build.Dir = filepath.Join("..", "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build the keeper: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type keeper struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Reader
	err *bytes.Buffer
	pub string
}

type response struct {
	Success   bool            `json:"success"`
	ErrorCode string          `json:"error_code"`
	Data      json.RawMessage `json:"data"`
}

func start(t *testing.T) *keeper {
	t.Helper()
	dir := t.TempDir()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := json.Marshal(map[string]string{
		config.Service + "|" + config.DragPassKeeperPrivateKey: pair.PrivateKey,
		config.Service + "|" + config.DragPassKeeperPublicKey:  pair.PublicKey,
	})
	if err := os.WriteFile(filepath.Join(dir, "keyring.json"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binaryPath)
	cmd.Env = []string{
		"KEEPER_E2E_MODE=1",
		"KEEPER_E2E_KEYRING_FILE=" + filepath.Join(dir, "keyring.json"),
		"HOME=" + filepath.Join(dir, "home"),
		"PATH=" + os.Getenv("PATH"),
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return &keeper{t: t, in: in, out: bufio.NewReader(out), err: stderr, pub: pair.PublicKey}
}

func (k *keeper) call(action string, payload any) response {
	k.t.Helper()
	body, _ := json.Marshal(payload)
	msg, _ := json.Marshal(proto.BaseRequest{Action: action, RequestID: "r", Payload: body})
	if err := binary.Write(k.in, binary.LittleEndian, uint32(len(msg))); err != nil {
		k.t.Fatal(err)
	}
	if _, err := k.in.Write(msg); err != nil {
		k.t.Fatal(err)
	}
	var n uint32
	if err := binary.Read(k.out, binary.LittleEndian, &n); err != nil {
		k.t.Fatalf("%s: no answer: %v", action, err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(k.out, buf); err != nil {
		k.t.Fatal(err)
	}
	var r response
	if err := json.Unmarshal(buf, &r); err != nil {
		k.t.Fatal(err)
	}
	return r
}

func (k *keeper) must(action string, payload, into any) {
	k.t.Helper()
	r := k.call(action, payload)
	if !r.Success {
		k.t.Fatalf("%s refused: %s", action, r.ErrorCode)
	}
	if into != nil {
		if err := json.Unmarshal(r.Data, into); err != nil {
			k.t.Fatal(err)
		}
	}
}

// openGroup wraps a fresh Group DEK to this Keeper's key and opens a handle.
func (k *keeper) openGroup() string {
	k.t.Helper()
	pub, err := crypto.ParsePublicKey(k.pub)
	if err != nil {
		k.t.Fatal(err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		k.t.Fatal(err)
	}
	wrapped, err := crypto.EncryptData(pub, dek)
	if err != nil {
		k.t.Fatal(err)
	}
	var out struct {
		GroupHandle string `json:"group_handle"`
	}
	k.must(proto.ActionGroupSessionOpen, map[string]any{"encrypted_group_dek": base64.StdEncoding.EncodeToString(wrapped)}, &out)
	return out.GroupHandle
}

type tracked struct {
	IVB64         string             `json:"iv_b64"`
	CiphertextB64 string             `json:"ciphertext_b64"`
	ChangeVerdict string             `json:"change_verdict"`
	ChangeRecord  proto.ChangeRecord `json:"change_record"`
}

func (k *keeper) save(handle string, dekVersion int, value string, prev *proto.ChangeRecord, prevHandle string) tracked {
	k.t.Helper()
	req := map[string]any{
		"group_handle": handle, "org_id": orgID, "group_id": groupID, "dek_version": dekVersion,
		"token_expiry": "never", "entry_id": entryID,
		"plaintext_b64": base64.StdEncoding.EncodeToString([]byte(value)),
	}
	if prev != nil {
		req["previous_record"] = prev
	}
	if prevHandle != "" {
		req["previous_group_handle"] = prevHandle
	}
	var out tracked
	k.must(proto.ActionGroupEncryptBoundTracked, req, &out)
	return out
}

func TestRealKeeper_TrackedEncryptRoundTrip(t *testing.T) {
	k := start(t)
	v7 := k.openGroup()
	first := k.save(v7, 7, "rt-value-one", nil, "")
	if first.ChangeVerdict != "baseline" || first.ChangeRecord.Seq != 1 {
		t.Fatalf("first save: %q seq %d, want baseline 1", first.ChangeVerdict, first.ChangeRecord.Seq)
	}
	same := k.save(v7, 7, "rt-value-one", &first.ChangeRecord, "")
	if same.ChangeVerdict != "same" {
		t.Fatalf("re-saving the value: %q, want same", same.ChangeVerdict)
	}
	// A new DEK version: the record under version 7 is opened through its own
	// handle and the value is still the same.
	v8 := k.openGroup()
	rotated := k.save(v8, 8, "rt-value-one", &same.ChangeRecord, v7)
	if rotated.ChangeVerdict != "same" || rotated.ChangeRecord.DekVersion != 8 {
		t.Fatalf("after rotation: %q version %d, want same 8", rotated.ChangeVerdict, rotated.ChangeRecord.DekVersion)
	}
	changed := k.save(v8, 8, "rt-value-two", &rotated.ChangeRecord, "")
	if changed.ChangeVerdict != "changed" {
		t.Fatalf("new value: %q, want changed", changed.ChangeVerdict)
	}
	// Without the old version's handle the comparison is unknown, never changed.
	unknown := k.save(v8, 8, "rt-value-two", &same.ChangeRecord, "")
	if unknown.ChangeVerdict != "unknown" {
		t.Fatalf("unverifiable record: %q, want unknown", unknown.ChangeVerdict)
	}
	// The first token still opens to the first value.
	k.must(proto.ActionGroupDecryptBoundToClipboard, map[string]any{
		"group_handle": v7, "org_id": orgID, "group_id": groupID, "dek_version": 7,
		"token_expiry": "never", "iv_b64": first.IVB64, "ciphertext_b64": first.CiphertextB64,
		"clipboard_ttl_ms": 30000,
	}, nil)
	var hash struct {
		HasHash     bool   `json:"has_hash"`
		LastHashB64 string `json:"last_hash_b64"`
	}
	k.must(proto.ActionClipboardGetLastHash, map[string]any{}, &hash)
	want := sha256.Sum256([]byte("rt-value-one"))
	if !hash.HasHash || hash.LastHashB64 != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatal("the first token no longer opens to its original value")
	}
	if bytes.Contains(k.err.Bytes(), []byte("rt-value")) {
		t.Fatal("the Keeper logged a test value")
	}
}
