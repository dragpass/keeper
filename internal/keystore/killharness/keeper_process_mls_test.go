//go:build mls && cgo && (darwin || linux)

// keeper_process_mls_test.go — the Keeper binary, the real MLS library, and a
// real SIGKILL.
//
// chatstate's own process tests (chat_state_process_test.go) kill a helper
// that runs the store against a fake cipher. These run the release entry
// point instead: `go build -tags "mls keeper_killseam"` of the module root,
// framed Native Messaging on stdin / stdout exactly as Chrome speaks it, every
// permit and challenge signed by a test server key the Keeper's own verifier
// checks, and the only thing standing in for ariadne is this test deciding
// which rows exist.
//
// **Why a seam and not a timed kill.** Every point below lies between two
// fsyncs of one call, microseconds apart; no signal sent from outside lands
// there on purpose. A keeper_killseam build parks the process at the point
// named by KEEPER_TEST_CRASH_AT and creates KEEPER_TEST_CRASH_MARK; the test
// then kills it with SIGKILL, so the process dies with the conversation lock
// held and nothing deferred run, as a real crash would. A build without the
// tag has no seam.
//
// Each Keeper has its own directory: the keyring file (KEEPER_E2E_MODE with
// KEEPER_E2E_KEYRING_FILE), the chat state root, and HOME. Nothing reaches the
// login keychain or ~/Library.

package killharness

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	hOrg    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	hConv   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	hAlice  = "a1111111-1111-4111-8111-111111111111"
	hBob    = "b2222222-2222-4222-8222-222222222222"
	hDevice = "d1111111-1111-4111-8111-111111111111"
	hNonce  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var (
	binaryPath string
	serverKey  *rsa.PrivateKey
	serverPEM  string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keeper-killharness-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "dragpass-keeper-killseam")
	build := exec.Command("go", "build", "-tags", "mls keeper_killseam", "-o", binaryPath, ".")
	build.Dir = filepath.Join("..", "..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build the keeper: %v\n%s", err, out)
		os.Exit(1)
	}
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	serverPEM = pair.PublicKey
	block, _ := pem.Decode([]byte(pair.PrivateKey))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err1 != nil {
			fmt.Fprintln(os.Stderr, err, err1)
			os.Exit(1)
		}
		parsed = key
	}
	serverKey = parsed.(*rsa.PrivateKey)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func sign(t *testing.T, token string) string {
	t.Helper()
	sig, err := crypto.SignData(serverKey, token)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// ────────────────────────────────────────────────────────────────────────
// One device: a directory, and at most one live Keeper process on it.
// ────────────────────────────────────────────────────────────────────────

type device struct {
	t       *testing.T
	account string
	dir     string
	commits int
}

func newDevice(t *testing.T, account string) *device {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"home", "chat-state"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seed := map[string]string{
		config.Service + "|" + config.DragPassServerPublicKeyVersionedPrefix + "1": serverPEM,
		config.Service + "|" + config.DragPassServerPublicKeyActiveVersion:         "1",
		config.Service + "|" + config.DragPassKeeperPrivateKey:                     pair.PrivateKey,
		config.Service + "|" + config.DragPassKeeperPublicKey:                      pair.PublicKey,
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keyring.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return &device{t: t, account: account, dir: dir}
}

func (d *device) stateRoot() string { return filepath.Join(d.dir, "chat-state") }

// anchors returns every chat anchor in the keyring file.
func (d *device) anchors() []chatstate.Anchor {
	d.t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.dir, "keyring.json"))
	if err != nil {
		d.t.Fatal(err)
	}
	var entries map[string]string
	if err := json.Unmarshal(raw, &entries); err != nil {
		d.t.Fatalf("keyring file: %v", err)
	}
	var out []chatstate.Anchor
	for key, value := range entries {
		if !strings.Contains(key, "anchor") {
			continue
		}
		var a chatstate.Anchor
		if json.Unmarshal([]byte(value), &a) == nil {
			out = append(out, a)
		}
	}
	return out
}

func (d *device) anchor() chatstate.Anchor {
	d.t.Helper()
	all := d.anchors()
	if len(all) != 1 {
		d.t.Fatalf("%d chat anchors in the keyring, want 1", len(all))
	}
	return all[0]
}

type keeperProc struct {
	t      *testing.T
	d      *device
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *bytes.Buffer
	mark   string
	done   chan error
	mu     sync.Mutex
}

// start runs the Keeper on this device. crashAt names a chatstate crash
// point, "" for none; skip lets that many earlier passes through it go by.
func (d *device) start(crashAt string, skip int) *keeperProc {
	d.t.Helper()
	cmd := exec.Command(binaryPath)
	mark := filepath.Join(d.dir, fmt.Sprintf("crash-mark-%d", time.Now().UnixNano()))
	cmd.Env = []string{
		"KEEPER_E2E_MODE=1",
		"KEEPER_E2E_KEYRING_FILE=" + filepath.Join(d.dir, "keyring.json"),
		chatstate.RootEnvVar + "=" + d.stateRoot(),
		"HOME=" + filepath.Join(d.dir, "home"),
		"PATH=" + os.Getenv("PATH"),
	}
	if crashAt != "" {
		cmd.Env = append(cmd.Env,
			"KEEPER_TEST_CRASH_AT="+crashAt,
			"KEEPER_TEST_CRASH_SKIP="+strconv.Itoa(skip),
			"KEEPER_TEST_CRASH_MARK="+mark)
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		d.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		d.t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		d.t.Fatal(err)
	}
	p := &keeperProc{t: d.t, d: d, cmd: cmd, in: in, out: bufio.NewReader(out), stderr: stderr,
		mark: mark, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	d.t.Cleanup(func() { p.kill() })
	return p
}

type response struct {
	Success   bool            `json:"success"`
	Error     string          `json:"error"`
	ErrorCode string          `json:"error_code"`
	Data      json.RawMessage `json:"data"`
}

func (p *keeperProc) send(action string, payload any) {
	p.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	msg, err := json.Marshal(proto.BaseRequest{Action: action, RequestID: "r", Payload: body})
	if err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := binary.Write(p.in, binary.LittleEndian, uint32(len(msg))); err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.in.Write(msg); err != nil {
		p.t.Fatal(err)
	}
}

func (p *keeperProc) receive() (response, error) {
	var n uint32
	if err := binary.Read(p.out, binary.LittleEndian, &n); err != nil {
		return response{}, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.out, buf); err != nil {
		return response{}, err
	}
	var r response
	if err := json.Unmarshal(buf, &r); err != nil {
		return response{}, err
	}
	return r, nil
}

func (p *keeperProc) call(action string, payload any) response {
	p.t.Helper()
	p.send(action, payload)
	r, err := p.receive()
	if err != nil {
		p.t.Fatalf("%s: no answer: %v\n%s", action, err, p.stderr.String())
	}
	return r
}

func (p *keeperProc) must(action string, payload any, into any) {
	p.t.Helper()
	r := p.call(action, payload)
	if !r.Success {
		p.t.Fatalf("%s as %s: %s (%s)", action, p.d.account[:8], r.Error, r.ErrorCode)
	}
	if into != nil {
		if err := json.Unmarshal(r.Data, into); err != nil {
			p.t.Fatalf("%s: %v", action, err)
		}
	}
}

func (p *keeperProc) refused(action string, payload any, code string) {
	p.t.Helper()
	if r := p.call(action, payload); r.Success || r.ErrorCode != code {
		p.t.Fatalf("%s = %+v; want %s", action, r, code)
	}
}

// parkAt sends a request that the crash point stops, and returns once the
// process is parked there.
func (p *keeperProc) parkAt(action string, payload any) {
	p.t.Helper()
	p.send(action, payload)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(p.mark); err == nil {
			return
		}
		select {
		case err := <-p.done:
			p.t.Fatalf("the keeper exited before the crash point: %v\n%s", err, p.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("the keeper never reached the crash point\n%s", p.stderr.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// kill is a SIGKILL and a wait for the process to be gone.
func (p *keeperProc) kill() {
	if p.cmd.ProcessState != nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		p.t.Error("the killed keeper did not exit")
	}
}

func (p *keeperProc) killAndAssertKilled() {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		p.t.Fatal(err)
	}
	err := <-p.done
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		p.t.Fatalf("the keeper did not die of SIGKILL: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The requests, signed the way ariadne would sign them.
// ────────────────────────────────────────────────────────────────────────

func (d *device) permit() proto.ChatStatePermit {
	now := time.Now().Unix()
	p := proto.ChatStatePermit{
		AccountID: d.account, OrgID: hOrg, ConversationID: hConv,
		PendingRemovalAccountIDs: []string{},
		PendingLeafReplacements:  []proto.ChatStateLeafReplacement{},
		PendingDeviceRevocations: []proto.MLSDeviceRef{},
		IssuedAt:                 now,
		ExpiresAt:                now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion:         1,
	}
	p.Signature = sign(d.t, proto.ChatStatePermitCanonical(p))
	return p
}

func (p *keeperProc) enrol() {
	p.t.Helper()
	d := p.d
	now := time.Now().Unix()
	challenge := "dragpass.mls.leaf.challenge|1|" + d.account + "|" + hDevice + "|" + hNonce + "|" +
		strconv.FormatInt(now+proto.MLSLeafChallengeTTLSeconds, 10)
	var declared proto.MLSLeafDeclareResponseData
	p.must(proto.ActionMLSLeafDeclare, proto.MLSLeafDeclareRequest{
		ChallengeToken: challenge, ServerSignature: sign(p.t, challenge), ServerKeyVersion: 1,
		AccountID: d.account, DeviceID: hDevice,
		NotBefore: now, NotAfter: now + proto.MLSLeafMaxValiditySeconds,
		Reason: proto.MLSLeafReasonEnroll,
	}, &declared)
	l := declared.MLSLeafDeclaration
	accepted := proto.MLSLeafAcceptedToken(l.AccountID, l.DeviceID, l.SignatureKeyFingerprint, l.NotBefore, l.NotAfter)
	p.must(proto.ActionMLSLeafPromote, proto.MLSLeafPromoteRequest{
		AcceptanceToken: accepted, ServerSignature: sign(p.t, accepted), ServerKeyVersion: 1,
	}, nil)
}

func (p *keeperProc) keyPackage() proto.MLSMemberKeyPackage {
	p.t.Helper()
	d := p.d
	challenge := "dragpass.mls.keypackage.challenge|1|" + d.account + "|" + hDevice + "|" + hNonce + "|" +
		strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10)
	var out proto.MLSKeyPackageGenerateResponseData
	p.must(proto.MLSKeyPackageGenerate, proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: challenge, ServerSignature: sign(p.t, challenge), ServerKeyVersion: 1,
		AccountID: d.account, DeviceID: hDevice, Count: 1,
	}, &out)
	kp := out.KeyPackages[0]
	return proto.MLSMemberKeyPackage{AccountID: d.account, DeviceID: hDevice, KeyPackageB64: kp.KeyPackageB64}
}

func (d *device) nextCommitID() string {
	d.commits++
	return d.account[:8] + "-7777-4777-8777-" + strconv.FormatInt(int64(700000000000+d.commits), 10)
}

func messageID(n int) string {
	return "eeeeeeee-eeee-4eee-8eee-" + strconv.FormatInt(int64(100000000000+n), 10)
}

func (d *device) encryptRequest(id string, epoch uint64, text string) proto.MLSEncryptRequest {
	return proto.MLSEncryptRequest{
		Permit: d.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientMessageID: id, ExpectedEpoch: epoch,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(text)),
	}
}

func (p *keeperProc) encrypt(id string, epoch uint64, text string) proto.MLSEncryptResponseData {
	p.t.Helper()
	var out proto.MLSEncryptResponseData
	p.must(proto.MLSEncrypt, p.d.encryptRequest(id, epoch, text), &out)
	return out
}

func (p *keeperProc) readOutbox(id string) proto.ChatStateReadOutboxResponseData {
	p.t.Helper()
	var out proto.ChatStateReadOutboxResponseData
	p.must(proto.ChatStateReadOutbox, proto.ChatStateReadOutboxRequest{
		Permit: p.d.permit(), OrgID: hOrg, ConversationID: hConv, ClientMessageID: id,
	}, &out)
	return out
}

func (d *device) decryptRequest(msgs ...proto.MLSDisplayMessage) proto.MLSDecryptBatchForAppDisplayRequest {
	return proto.MLSDecryptBatchForAppDisplayRequest{
		Permit: d.permit(), OrgID: hOrg, ConversationID: hConv, Messages: msgs,
	}
}

type displayed struct {
	PlaintextB64 []string               `json:"plaintext_b64"`
	Items        []proto.MLSDisplayItem `json:"items"`
}

func (p *keeperProc) decrypt(msgs ...proto.MLSDisplayMessage) displayed {
	p.t.Helper()
	var out displayed
	p.must(proto.MLSDecryptBatchForAppDisplay, p.d.decryptRequest(msgs...), &out)
	return out
}

func (p *keeperProc) status() proto.MLSConversationStatusResponseData {
	p.t.Helper()
	var out proto.MLSConversationStatusResponseData
	p.must(proto.MLSConversationStatus, proto.MLSConversationStatusRequest{
		Permit: p.d.permit(), OrgID: hOrg, ConversationID: hConv,
	}, &out)
	return out
}

func (p *keeperProc) buildUpdate(id string, expected uint64) proto.MLSCommitResponseData {
	p.t.Helper()
	var out proto.MLSCommitResponseData
	p.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: p.d.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: id, ExpectedEpoch: expected, UpdateSelf: true,
	}, &out)
	return out
}

func (d *device) confirmRequest(id string) proto.MLSCommitConfirmRequest {
	return proto.MLSCommitConfirmRequest{
		Permit: d.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: id, Outcome: proto.MLSCommitOutcomeAccepted,
	}
}

func (d *device) processRequest(seq, epoch uint64, commitB64 string) proto.MLSProcessRequest {
	return proto.MLSProcessRequest{
		Permit: d.permit(), OrgID: hOrg, ConversationID: hConv,
		Seq: seq, Epoch: epoch, CommitB64: commitB64,
	}
}

func text(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ────────────────────────────────────────────────────────────────────────
// The conversation: Alice creates it with Bob's KeyPackage, the "server"
// accepts the Add, Bob joins from the Welcome. Both at epoch 1.
// ────────────────────────────────────────────────────────────────────────

type conversation struct {
	t          *testing.T
	alice, bob *device
	seq        uint64
}

func (c *conversation) nextSeq() uint64 {
	c.seq++
	return c.seq
}

func newConversation(t *testing.T) *conversation {
	t.Helper()
	alice, bob := newDevice(t, hAlice), newDevice(t, hBob)
	a, b := alice.start("", 0), bob.start("", 0)
	a.enrol()
	b.enrol()
	id := alice.nextCommitID()
	var built proto.MLSCommitResponseData
	a.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{b.keyPackage()},
	}, &built)
	a.must(proto.MLSCommitConfirm, alice.confirmRequest(id), nil)
	var joined proto.MLSJoinResponseData
	b.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: hOrg, ConversationID: hConv, WelcomeB64: built.WelcomeB64,
	}, &joined)
	if joined.Epoch != 1 {
		t.Fatalf("bob joined at epoch %d", joined.Epoch)
	}
	a.in.Close()
	b.in.Close()
	<-a.done
	<-b.done
	return &conversation{t: t, alice: alice, bob: bob, seq: 1}
}

// positions collects every ciphertext a sender produced by the position it
// declares, and fails on two different ciphertexts at one position: the
// (key, nonce) reuse this whole design exists to prevent.
type positions map[string]string

func (ps positions) add(t *testing.T, sent proto.MLSEncryptResponseData) {
	t.Helper()
	key := fmt.Sprintf("%d/%d/%s/%d", sent.Epoch, sent.LeafIndex, sent.ContentType, sent.Generation)
	if prev, ok := ps[key]; ok && prev != sent.CiphertextB64 {
		t.Fatalf("two different ciphertexts at position %s", key)
	}
	ps[key] = sent.CiphertextB64
}
