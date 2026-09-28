//go:build mls && cgo

// chat_revocation_process_mls_test.go — Extension logout and device reset
// against an App that is in the middle of chat work, with real processes.
//
// The owner is the release entry point built with the MLS library, run as the
// App service; the Extension is a second Keeper process speaking Native
// Messaging on stdio and proxying to it, as Chrome would launch it; the App is
// a local RPC client over real HTTP. Every permit and challenge is signed by a
// test server key the owner's own verifier checks. The App leaves a message
// encrypted but not yet marked sent, or a Commit built but not yet confirmed,
// the Extension revokes, and nothing the old runtime sends afterwards lands.

package localrpc

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	keepercrypto "github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/localsecret"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	rvOrg     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	rvConv    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	rvAccount = "a1111111-1111-4111-8111-111111111111"
	rvDevice  = "d1111111-1111-4111-8111-111111111111"
	rvNonce   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rvBob     = "b2222222-2222-4222-8222-222222222222"
	rvBobDev  = "d2222222-2222-4222-8222-222222222222"
)

var (
	mlsKeeperOnce   sync.Once
	mlsKeeperBinary string
	mlsKeeperErr    error
)

func builtMLSKeeper(t *testing.T) string {
	t.Helper()
	mlsKeeperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "keeper-localrpc-mls-")
		if err != nil {
			mlsKeeperErr = err
			return
		}
		name := "dragpass-keeper-mls"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		mlsKeeperBinary = filepath.Join(dir, name)
		build := exec.Command("go", "build", "-tags", "mls", "-o", mlsKeeperBinary, ".")
		build.Dir = filepath.Join("..", "..", "..")
		build.Env = append(os.Environ(), "CGO_ENABLED=1")
		if out, err := build.CombinedOutput(); err != nil {
			mlsKeeperErr = fmt.Errorf("build the MLS keeper: %v\n%s", err, out)
		}
	})
	if mlsKeeperErr != nil {
		t.Fatal(mlsKeeperErr)
	}
	return mlsKeeperBinary
}

// rvServer is the test's stand-in for ariadne's signing key.
type rvServer struct {
	key       *rsa.PrivateKey
	publicPEM string
}

func newRVServer(t *testing.T) rvServer {
	t.Helper()
	pair, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pair.PrivateKey))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			t.Fatal(err)
		}
	}
	return rvServer{key: parsed.(*rsa.PrivateKey), publicPEM: pair.PublicKey}
}

// rvDeviceDir is one device: its keyring file, chat state root, local secret
// and home, all under one test directory.
type rvDeviceDir struct {
	dir       string
	address   string
	serverKey *rsa.PrivateKey
}

func newRevocationDevice(t *testing.T, server rvServer) *rvDeviceDir {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"home", "chat-state", "local"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keeper, err := keepercrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := json.Marshal(map[string]string{
		config.Service + "|" + config.DragPassServerPublicKeyVersionedPrefix + "1": server.publicPEM,
		config.Service + "|" + config.DragPassServerPublicKeyActiveVersion:         "1",
		config.Service + "|" + config.DragPassKeeperPrivateKey:                     keeper.PrivateKey,
		config.Service + "|" + config.DragPassKeeperPublicKey:                      keeper.PublicKey,
	})
	if err := os.WriteFile(filepath.Join(dir, "keyring.json"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return &rvDeviceDir{dir: dir, address: reservedAddress(t), serverKey: server.key}
}

func (d *rvDeviceDir) env() []string {
	home := filepath.Join(d.dir, "home")
	return []string{
		"KEEPER_E2E_MODE=1",
		"KEEPER_E2E_KEYRING_FILE=" + filepath.Join(d.dir, "keyring.json"),
		chatstate.RootEnvVar + "=" + filepath.Join(d.dir, "chat-state"),
		localsecret.DirEnvVar + "=" + filepath.Join(d.dir, "local"),
		AddressEnvVar + "=" + d.address,
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"TEMP=" + os.TempDir(),
		"TMP=" + os.TempDir(),
		"USERPROFILE=" + home,
		"APPDATA=" + filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA=" + filepath.Join(home, "AppData", "Local"),
	}
}

func (d *rvDeviceDir) sign(t *testing.T, token string) string {
	t.Helper()
	sig, err := keepercrypto.SignData(d.serverKey, token)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (d *rvDeviceDir) permit(t *testing.T) proto.ChatStatePermit {
	now := time.Now().Unix()
	p := proto.ChatStatePermit{
		AccountID: rvAccount, OrgID: rvOrg, ConversationID: rvConv,
		PendingRemovalAccountIDs: []string{},
		PendingLeafReplacements:  []proto.ChatStateLeafReplacement{},
		PendingDeviceRevocations: []proto.MLSDeviceRef{},
		IssuedAt:                 now,
		ExpiresAt:                now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion:         1,
	}
	p.Signature = d.sign(t, proto.ChatStatePermitCanonical(p))
	return p
}

func (d *rvDeviceDir) startOwner(t *testing.T) *keeperProcess {
	t.Helper()
	cmd := exec.Command(builtMLSKeeper(t), "--app-service")
	cmd.Env = d.env()
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &keeperProcess{cmd: cmd, stderr: stderr, exited: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exited) }()
	t.Cleanup(p.kill)
	probe := &testAppClient{address: d.address, origin: testOrigin}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if response, err := probe.do(http.MethodGet, "/v1/health", nil, false); err == nil {
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
	t.Fatalf("keeper did not serve %s\n%s", d.address, stderr.String())
	return nil
}

func (d *rvDeviceDir) startExtension(t *testing.T) *nativeHost {
	t.Helper()
	return d.startNative(t, d.env())
}

func (d *rvDeviceDir) startNative(t *testing.T, env []string) *nativeHost {
	t.Helper()
	cmd := exec.Command(builtMLSKeeper(t))
	cmd.Env = env
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

func (d *rvDeviceDir) app(t *testing.T) *testAppClient {
	t.Helper()
	t.Setenv(localsecret.DirEnvVar, filepath.Join(d.dir, "local"))
	secret, err := localsecret.Load()
	if err != nil {
		t.Fatal(err)
	}
	client := &testAppClient{address: d.address, origin: testOrigin, pairingKey: secret.AppPairingKey()}
	if err := client.open(); err != nil {
		t.Fatalf("open session: %v", err)
	}
	return client
}

// chatStateOnDisk lists the chat state records and the chat state keyring
// slots left on this device.
func (d *rvDeviceDir) chatStateOnDisk(t *testing.T) []string {
	t.Helper()
	var left []string
	_ = filepath.Walk(filepath.Join(d.dir, "chat-state"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".state") {
			left = append(left, path)
		}
		return nil
	})
	raw, err := os.ReadFile(filepath.Join(d.dir, "keyring.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]string
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("keyring file: %v", err)
	}
	for key := range entries {
		if strings.Contains(key, config.ChatStateSealKeyPrefix) || strings.Contains(key, config.ChatStateAnchorPrefix) {
			left = append(left, key)
		}
	}
	return left
}

type rvResult struct {
	Success   bool            `json:"success"`
	Error     string          `json:"error"`
	ErrorCode string          `json:"error_code"`
	Data      json.RawMessage `json:"data"`
}

func rvCall(t *testing.T, client *testAppClient, path string, body any) rvResult {
	t.Helper()
	response, err := client.call(path, body)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	raw, _ := json.Marshal(response)
	var result rvResult
	_ = json.Unmarshal(raw, &result)
	return result
}

func rvMust(t *testing.T, client *testAppClient, path string, body any, into any) {
	t.Helper()
	result := rvCall(t, client, path, body)
	if !result.Success {
		t.Fatalf("%s: %s (%s)", path, result.Error, result.ErrorCode)
	}
	if into != nil {
		if err := json.Unmarshal(result.Data, into); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func rvSignature(client *testAppClient, method, path string, n int) map[string]string {
	return map[string]string{
		"method": method, "path": path, "query": "",
		"timestamp":   strconv.FormatInt(time.Now().Unix(), 10),
		"nonce":       base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("nonce-%010d-pad", n))),
		"body_sha256": strings.Repeat("0", 64),
		"account_id":  rvAccount,
		"token_id":    "22222222-2222-4222-8222-222222222222",
		"device_id":   "device-12345678",
	}
}

func frame(t *testing.T, action string, payload any) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := json.Marshal(proto.BaseRequest{Action: action, RequestID: "r", Payload: body})
	if err != nil {
		t.Fatal(err)
	}
	return string(msg)
}

func mustNative(t *testing.T, host *nativeHost, action string, payload any, into any) {
	t.Helper()
	response := host.send(t, frame(t, action, payload))
	if !response.Success {
		t.Fatalf("%s: %s (%s)\n%s", action, response.Error, response.ErrorCode, host.stderr.String())
	}
	if into != nil {
		raw, _ := json.Marshal(response.Data)
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
}

func leafDeclaration(d *rvDeviceDir, t *testing.T, account, device string) proto.MLSLeafDeclareRequest {
	now := time.Now().Unix()
	challenge := "dragpass.mls.leaf.challenge|1|" + account + "|" + device + "|" + rvNonce + "|" +
		strconv.FormatInt(now+proto.MLSLeafChallengeTTLSeconds, 10)
	return proto.MLSLeafDeclareRequest{
		ChallengeToken: challenge, ServerSignature: d.sign(t, challenge), ServerKeyVersion: 1,
		AccountID: account, DeviceID: device,
		NotBefore: now, NotAfter: now + proto.MLSLeafMaxValiditySeconds,
		Reason: proto.MLSLeafReasonEnroll,
	}
}

func (d *rvDeviceDir) promotion(t *testing.T, declared proto.MLSLeafDeclareResponseData) proto.MLSLeafPromoteRequest {
	l := declared.MLSLeafDeclaration
	accepted := proto.MLSLeafAcceptedToken(l.AccountID, l.DeviceID, l.SignatureKeyFingerprint, l.NotBefore, l.NotAfter)
	return proto.MLSLeafPromoteRequest{AcceptanceToken: accepted, ServerSignature: d.sign(t, accepted), ServerKeyVersion: 1}
}

// bobKeyPackage is the room's other member: a standalone Keeper of its own
// (no local secret, so no owner and no listener) that enrols and hands out
// one KeyPackage.
func bobKeyPackage(t *testing.T, server rvServer) proto.MLSMemberKeyPackage {
	t.Helper()
	bob := newRevocationDevice(t, server)
	var env []string
	for _, entry := range bob.env() {
		if !strings.HasPrefix(entry, localsecret.DirEnvVar+"=") && !strings.HasPrefix(entry, AddressEnvVar+"=") {
			env = append(env, entry)
		}
	}
	host := bob.startNative(t, env)
	var declared proto.MLSLeafDeclareResponseData
	mustNative(t, host, proto.ActionMLSLeafDeclare, leafDeclaration(bob, t, rvBob, rvBobDev), &declared)
	mustNative(t, host, proto.ActionMLSLeafPromote, bob.promotion(t, declared), nil)
	challenge := "dragpass.mls.keypackage.challenge|1|" + rvBob + "|" + rvBobDev + "|" + rvNonce + "|" +
		strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10)
	var generated proto.MLSKeyPackageGenerateResponseData
	mustNative(t, host, proto.MLSKeyPackageGenerate, proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: challenge, ServerSignature: bob.sign(t, challenge), ServerKeyVersion: 1,
		AccountID: rvBob, DeviceID: rvBobDev, Count: 1,
	}, &generated)
	return proto.MLSMemberKeyPackage{AccountID: rvBob, DeviceID: rvBobDev, KeyPackageB64: generated.KeyPackages[0].KeyPackageB64}
}

// setUpRoom has the App take the lease, enrol this device's leaf and create
// the room, the way the App's chat runtime does before its first send.
func setUpRoom(t *testing.T, d *rvDeviceDir, client *testAppClient, bob proto.MLSMemberKeyPackage) {
	t.Helper()
	rvMust(t, client, "/v1/auth/login/ensure-request-key", map[string]any{}, nil)
	if claim, err := client.claim(routeHolder); err != nil || !claim.Success || client.epoch == "" {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	var declared proto.MLSLeafDeclareResponseData
	rvMust(t, client, "/v1/chat/"+proto.ActionMLSLeafDeclare, leafDeclaration(d, t, rvAccount, rvDevice), &declared)
	rvMust(t, client, "/v1/chat/"+proto.ActionMLSLeafPromote, d.promotion(t, declared), nil)
	create := "a1111111-7777-4777-8777-700000000001"
	rvMust(t, client, "/v1/chat/"+proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
		ClientCommitID: create, Members: []proto.MLSMemberKeyPackage{bob},
	}, nil)
	rvMust(t, client, "/v1/chat/"+proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
		ClientCommitID: create, Outcome: proto.MLSCommitOutcomeAccepted,
	}, nil)
}

func assertRevoked(t *testing.T, what string, result rvResult, reason string) {
	t.Helper()
	var data struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(result.Data, &data)
	if result.Success || result.ErrorCode != keystore.ErrCodeChatRuntimeRevoked || data.Reason != reason {
		t.Fatalf("%s after the revocation: %+v", what, result)
	}
}

// Every write the old runtime could still attempt, each refused as revoked.
func assertOldRuntimeFenced(t *testing.T, d *rvDeviceDir, client *testAppClient, bob proto.MLSMemberKeyPackage, reason, messageID, commitID string) {
	t.Helper()
	conversation := "/api/v1/conversations/" + rvConv
	for _, attempt := range []struct {
		what, path string
		body       any
	}{
		{"mark sent", "/v1/chat/" + proto.MLSMarkSent, proto.MLSMarkSentRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv, ClientMessageID: messageID, Seq: 2}},
		{"read outbox", "/v1/chat/" + proto.ChatStateReadOutbox, proto.ChatStateReadOutboxRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv, ClientMessageID: messageID}},
		{"encrypt again", "/v1/chat/" + proto.MLSEncrypt, proto.MLSEncryptRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
			ClientMessageID: "eeeeeeee-eeee-4eee-8eee-100000000009", ExpectedEpoch: 1,
			PlaintextB64: base64.StdEncoding.EncodeToString([]byte("after"))}},
		{"commit confirm", "/v1/chat/" + proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
			ClientCommitID: commitID, Outcome: proto.MLSCommitOutcomeAccepted}},
		{"commit abandon", "/v1/chat/" + proto.MLSCommitAbandon, proto.MLSCommitAbandonRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv, ClientCommitID: commitID}},
		{"process", "/v1/chat/" + proto.MLSProcess, proto.MLSProcessRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv, Seq: 3, Epoch: 1, CommitB64: "AAAA"}},
		{"group create", "/v1/chat/" + proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
			Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
			ClientCommitID: "a1111111-7777-4777-8777-700000000009", Members: []proto.MLSMemberKeyPackage{bob}}},
		{"sign message send", "/v1/request-signature", rvSignature(client, "POST", conversation+"/messages", 101)},
		{"sign commit post", "/v1/request-signature", rvSignature(client, "POST", conversation+"/mls/commit", 201)},
		{"reclaim", "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder, "epoch": client.epoch}},
	} {
		assertRevoked(t, attempt.what, rvCall(t, client, attempt.path, attempt.body), reason)
	}
	if left := d.chatStateOnDisk(t); len(left) != 0 {
		t.Fatalf("chat state left after the revocation: %v", left)
	}
}

func TestExtensionRevocationFencesAnAppMidSendAndMidCommit(t *testing.T) {
	revocations := []struct {
		name, frame, reason string
	}{
		{"logout purge", `{"action":"chat_state_purge","request_id":"ext","payload":{"owner_account_id":"` + rvAccount + `"}}`, keystore.ChatRuntimeRevokedPurged},
		{"device reset", `{"action":"reset_device_identity","request_id":"ext","payload":{}}`, keystore.ChatRuntimeRevokedReset},
	}
	server := newRVServer(t)
	bob := bobKeyPackage(t, server)
	for _, revocation := range revocations {
		t.Run(revocation.name+"/mid-send", func(t *testing.T) {
			d := newRevocationDevice(t, server)
			owner := d.startOwner(t)
			client := d.app(t)
			setUpRoom(t, d, client, bob)

			// The message is encrypted and in the outbox; the server POST and
			// mark_sent are still ahead.
			messageID := "eeeeeeee-eeee-4eee-8eee-100000000001"
			rvMust(t, client, "/v1/chat/"+proto.MLSEncrypt, proto.MLSEncryptRequest{
				Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
				ClientMessageID: messageID, ExpectedEpoch: 1,
				PlaintextB64: base64.StdEncoding.EncodeToString([]byte("hello")),
			}, nil)
			rvMust(t, client, "/v1/request-signature", rvSignature(client, "POST", "/api/v1/conversations/"+rvConv+"/messages", 1), nil)

			host := d.startExtension(t)
			if result := host.send(t, revocation.frame); !result.Success {
				t.Fatalf("Extension %s while the App is mid-send: %+v\n%s", revocation.name, result, owner.stderr.String())
			}
			assertOldRuntimeFenced(t, d, client, bob, revocation.reason, messageID, "a1111111-7777-4777-8777-700000000002")

			// A restart reads the moved epoch back: the old one stays revoked.
			owner.kill()
			d.startOwner(t)
			restarted := d.app(t)
			restarted.epoch = client.epoch
			assertRevoked(t, "reclaim after a restart",
				rvCall(t, restarted, "/v1/chat/runtime/claim", map[string]string{"holder_id": routeHolder, "epoch": client.epoch}),
				revocation.reason)
		})

		t.Run(revocation.name+"/mid-commit", func(t *testing.T) {
			d := newRevocationDevice(t, server)
			owner := d.startOwner(t)
			client := d.app(t)
			setUpRoom(t, d, client, bob)

			// An Update Commit is built and pending; the POST to the server and
			// the confirm are still ahead.
			commitID := "a1111111-7777-4777-8777-700000000002"
			rvMust(t, client, "/v1/chat/"+proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
				Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
				ClientCommitID: commitID, ExpectedEpoch: 1, UpdateSelf: true,
			}, nil)

			// The confirm races the revocation: it either lands first and is
			// erased with the rest, or it is fenced. Nothing survives either way.
			host := d.startExtension(t)
			raced := make(chan rvResult, 1)
			start := make(chan struct{})
			go func() {
				<-start
				response, err := client.call("/v1/chat/"+proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
					Permit: d.permit(t), OrgID: rvOrg, ConversationID: rvConv,
					ClientCommitID: commitID, Outcome: proto.MLSCommitOutcomeAccepted,
				})
				if err != nil {
					t.Errorf("raced confirm: %v", err)
				}
				raw, _ := json.Marshal(response)
				var result rvResult
				_ = json.Unmarshal(raw, &result)
				raced <- result
			}()
			close(start)
			if result := host.send(t, revocation.frame); !result.Success {
				t.Fatalf("Extension %s while the App is mid-Commit: %+v\n%s", revocation.name, result, owner.stderr.String())
			}
			if result := <-raced; !result.Success && result.ErrorCode != keystore.ErrCodeChatRuntimeRevoked {
				t.Fatalf("raced confirm neither landed first nor was fenced: %+v", result)
			}
			assertOldRuntimeFenced(t, d, client, bob, revocation.reason, "eeeeeeee-eeee-4eee-8eee-100000000001", commitID)
		})
	}
}
