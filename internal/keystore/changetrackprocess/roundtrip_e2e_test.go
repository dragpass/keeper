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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
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
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
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

const (
	accountID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	deviceID  = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	tokenID   = "ffffffff-ffff-4fff-8fff-ffffffffffff"
)

var serverKey *rsa.PrivateKey

func start(t *testing.T) *keeper {
	t.Helper()
	dir := t.TempDir()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if serverKey == nil {
		if serverKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
	}
	serverPEM, err := crypto.PublicKeyToPEM(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	store := testdouble.NewMemorySecretStore()
	for k, v := range map[string]string{
		config.DragPassKeeperPrivateKey:                     pair.PrivateKey,
		config.DragPassKeeperPublicKey:                      pair.PublicKey,
		config.DragPassServerPublicKeyVersionedPrefix + "1": serverPEM,
		config.DragPassServerPublicKeyActiveVersion:         "1",
		config.DeviceID: deviceID,
	} {
		if err := store.Set(config.Service, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := keychain.SetAccountBinding(store, accountID, "alice", true); err != nil {
		t.Fatal(err)
	}
	seed, _ := json.Marshal(store.Snapshot())
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
	if runtime.GOOS == "windows" {
		// What a Windows process needs beyond that: the system root (DLL
		// loading, the CSPRNG) and profile directories inside the test dir,
		// as the kill harness gives its Keepers.
		cmd.Env = append(cmd.Env,
			"SystemRoot="+os.Getenv("SystemRoot"), "SYSTEMROOT="+os.Getenv("SystemRoot"),
			"TEMP="+os.TempDir(), "TMP="+os.TempDir(),
			"USERPROFILE="+filepath.Join(dir, "home"),
			"APPDATA="+filepath.Join(dir, "home", "AppData", "Roaming"),
			"LOCALAPPDATA="+filepath.Join(dir, "home", "AppData", "Local"))
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
	return k.openGroupWith(nil)
}

// openGroupWith opens a handle, labeled when grantContext is set.
func (k *keeper) openGroupWith(grantContext *proto.GrantContext) string {
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
	req := map[string]any{"encrypted_group_dek": base64.StdEncoding.EncodeToString(wrapped)}
	if grantContext != nil {
		req["grant_context"] = grantContext
		req["org_id"] = grantContext.OrgID
	}
	k.must(proto.ActionGroupSessionOpen, req, &out)
	return out.GroupHandle
}

type tracked struct {
	IVB64         string             `json:"iv_b64"`
	CiphertextB64 string             `json:"ciphertext_b64"`
	ChangeVerdict string             `json:"change_verdict"`
	ChangeRecord  proto.ChangeRecord `json:"change_record"`
}

func (k *keeper) save(handle string, dekVersion int, value string, prev *proto.ChangeRecord, prevHandle string, dec *proto.ChangeCompareDecision) tracked {
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
	if dec != nil {
		req["compare_decision"] = dec
	}
	var out tracked
	k.must(proto.ActionGroupEncryptBoundTracked, req, &out)
	return out
}

// decide prepares a comparison in Keeper and signs the decision the API
// would issue for it.
func (k *keeper) decide(handle string, dekVersion int, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
	k.t.Helper()
	var prepared proto.GroupChangeComparePrepareResponseData
	k.must(proto.ActionGroupChangeComparePrepare, proto.GroupChangeComparePrepareRequest{
		GroupHandle: handle, OrgID: orgID, GroupID: groupID, DekVersion: dekVersion, EntryID: entryID,
		PreviousRecord: prev, TokenID: tokenID, SessionIssuedAtNanos: "1793410000123456789",
	}, &prepared)
	now := time.Now().Unix()
	d := proto.ChangeCompareDecision{
		Challenge: prepared.Challenge, AccountID: accountID, DeviceID: deviceID, TokenID: tokenID,
		SessionIssuedAtNanos: 1793410000123456789, OrgID: orgID, GroupID: groupID, DekVersion: dekVersion,
		GrantDigest: prepared.GrantDigest, EntryID: entryID, RecordDigest: prepared.RecordDigest,
		OperationDigest: prepared.OperationDigest, IssuedAt: now - 1, ExpiresAt: now + 9, ServerKeyVersion: 1,
	}
	sig, err := crypto.SignData(serverKey, proto.ChangeCompareDecisionCanonical(d))
	if err != nil {
		k.t.Fatal(err)
	}
	d.Signature = base64.StdEncoding.EncodeToString(sig)
	return &d
}

func legacy(v int) *proto.GrantContext {
	return &proto.GrantContext{Policy: proto.GrantPolicyLegacy, OrgID: orgID, GroupID: groupID, DekVersion: v}
}

func TestRealKeeper_TrackedEncryptRoundTrip(t *testing.T) {
	k := start(t)
	v7 := k.openGroupWith(legacy(7))
	first := k.save(v7, 7, "rt-value-one", nil, "", nil)
	if first.ChangeVerdict != "baseline" || first.ChangeRecord.Seq != 1 {
		t.Fatalf("first save: %q seq %d, want baseline 1", first.ChangeVerdict, first.ChangeRecord.Seq)
	}
	// No decision: no verdict, the value is still sealed.
	if got := k.save(v7, 7, "rt-value-one", &first.ChangeRecord, "", nil); got.ChangeVerdict != "unknown" || got.CiphertextB64 == "" {
		t.Fatalf("without a decision: %q, want unknown", got.ChangeVerdict)
	}
	same := k.save(v7, 7, "rt-value-one", &first.ChangeRecord, "", k.decide(v7, 7, first.ChangeRecord))
	if same.ChangeVerdict != "same" {
		t.Fatalf("re-saving the value under a decision: %q, want same", same.ChangeVerdict)
	}
	// A new DEK version: the record under version 7 is opened through its own
	// handle and the value is still the same.
	v8 := k.openGroupWith(legacy(8))
	rotated := k.save(v8, 8, "rt-value-one", &same.ChangeRecord, v7, k.decide(v8, 8, same.ChangeRecord))
	if rotated.ChangeVerdict != "same" || rotated.ChangeRecord.DekVersion != 8 {
		t.Fatalf("after rotation: %q version %d, want same 8", rotated.ChangeVerdict, rotated.ChangeRecord.DekVersion)
	}
	dec := k.decide(v8, 8, rotated.ChangeRecord)
	changed := k.save(v8, 8, "rt-value-two", &rotated.ChangeRecord, "", dec)
	if changed.ChangeVerdict != "changed" {
		t.Fatalf("new value: %q, want changed", changed.ChangeVerdict)
	}
	// The same decision answers no second guess.
	if again := k.save(v8, 8, "rt-value-one", &rotated.ChangeRecord, "", dec); again.ChangeVerdict != "unknown" {
		t.Fatalf("replayed decision: %q, want unknown", again.ChangeVerdict)
	}
	// Without the old version's handle the comparison is unknown, never changed.
	unknown := k.save(v8, 8, "rt-value-two", &same.ChangeRecord, "", k.decide(v8, 8, same.ChangeRecord))
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

// The baseline action on a real Keeper: an unexpired bound token, a signed
// decision for this account, device and session, one use; the baseline then
// describes the token's value. A decision the server did not sign gets no
// record.
func TestRealKeeper_ChangeBaselineFromAToken(t *testing.T) {
	k := start(t)
	gc := &proto.GrantContext{Policy: proto.GrantPolicyLegacy, OrgID: orgID, GroupID: groupID, DekVersion: 7}
	handle := k.openGroupWith(gc)
	var sealed struct {
		IVB64         string `json:"iv_b64"`
		CiphertextB64 string `json:"ciphertext_b64"`
	}
	k.must(proto.ActionGroupEncryptBound, map[string]any{
		"group_handle": handle, "org_id": orgID, "group_id": groupID, "dek_version": 7,
		"token_expiry": "never", "plaintext_b64": base64.StdEncoding.EncodeToString([]byte("rt-base-value")),
	}, &sealed)
	prepare := proto.GroupChangeBaselinePrepareRequest{
		GroupHandle: handle, Token: "RT-TOKEN", OrgID: orgID, GroupID: groupID, DekVersion: 7,
		TokenExpiry: "never", IVB64: sealed.IVB64, CiphertextB64: sealed.CiphertextB64,
		EntryID: entryID, TokenID: tokenID, SessionIssuedAtNanos: "1793410000123456789",
	}
	decide := func(sign bool) proto.ChangeBaselineDecision {
		var prepared proto.GroupChangeBaselinePrepareResponseData
		k.must(proto.ActionGroupChangeBaselinePrepare, prepare, &prepared)
		now := time.Now().Unix()
		d := proto.ChangeBaselineDecision{
			Challenge: prepared.Challenge, AccountID: accountID, DeviceID: deviceID, TokenID: tokenID,
			SessionIssuedAtNanos: 1793410000123456789, OrgID: orgID, GroupID: groupID, DekVersion: 7,
			GrantDigest: prepared.GrantDigest, EntryID: entryID, TokenFingerprint: prepared.TokenFingerprint,
			OperationDigest: prepared.OperationDigest, IssuedAt: now - 1, ExpiresAt: now + 9, ServerKeyVersion: 1,
		}
		d.Signature = base64.StdEncoding.EncodeToString([]byte("unsigned"))
		if sign {
			sig, err := crypto.SignData(serverKey, proto.ChangeBaselineDecisionCanonical(d))
			if err != nil {
				t.Fatal(err)
			}
			d.Signature = base64.StdEncoding.EncodeToString(sig)
		}
		return d
	}
	if r := k.call(proto.ActionGroupChangeBaselineExecute, map[string]any{"prepare": prepare, "decision": decide(false)}); r.Success {
		t.Fatal("an unsigned decision produced a baseline")
	}
	signed := decide(true)
	var baseline struct {
		ChangeVerdict string             `json:"change_verdict"`
		ChangeRecord  proto.ChangeRecord `json:"change_record"`
	}
	k.must(proto.ActionGroupChangeBaselineExecute, map[string]any{"prepare": prepare, "decision": signed}, &baseline)
	if baseline.ChangeVerdict != "baseline" || baseline.ChangeRecord.Seq != 1 {
		t.Fatalf("baseline %q seq %d", baseline.ChangeVerdict, baseline.ChangeRecord.Seq)
	}
	if r := k.call(proto.ActionGroupChangeBaselineExecute, map[string]any{"prepare": prepare, "decision": signed}); r.Success {
		t.Fatal("a decision was used twice")
	}
	if got := k.save(handle, 7, "rt-base-value", &baseline.ChangeRecord, "", k.decide(handle, 7, baseline.ChangeRecord)); got.ChangeVerdict != "same" {
		t.Fatalf("saving the token's value against the baseline: %q, want same", got.ChangeVerdict)
	}
	legacy := prepare
	legacy.TokenExpiry = ""
	if r := k.call(proto.ActionGroupChangeBaselinePrepare, legacy); r.Success || r.ErrorCode != proto.TokenLegacyRefused {
		t.Fatalf("a legacy token was admitted: %s", r.ErrorCode)
	}
	if bytes.Contains(k.err.Bytes(), []byte("rt-base")) {
		t.Fatal("the Keeper logged a test value")
	}
}
