// app_session_refresh_signature_test.go — the dp-app-refresh-v1 golden vector
// and the sign_app_session_refresh contract.
//
// The golden canonical and signature are shared with ariadne
// (middlewares/app_refresh_signature_test.go) and dragpass
// (@dragpass/request-canonicalization). A change here that is not made on all
// three sides breaks the App's session refresh under a required signature
// mode.

package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Public test fixture, never used outside tests.
var goldenAppRefreshSeed = func() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}()

func goldenAppRefreshRequest() proto.SignAppSessionRefreshRequest {
	return proto.SignAppSessionRefreshRequest{
		Origin:    "https://app.dragpass.io",
		Timestamp: "1789000000",
		Nonce:     "AAECAwQFBgcICQoLDA0ODw",
		// sha256("{}"), the body the App refresh sends.
		BodySHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		// base64url(sha256("dragpass-app-session-v1\ngolden-csrf")).
		AppBinding: "-B5iTp-AXzAzRyRT3PzNPt9ukdY5HYIabH8Lc3Gyquk",
		DeviceID:   "33333333-3333-4333-8333-333333333333",
	}
}

const goldenAppRefreshCanonical = "dp-app-refresh-v1\n" +
	"POST\n" +
	"/api/v1/auth/app-session\n" +
	"https://app.dragpass.io\n" +
	"1789000000\n" +
	"AAECAwQFBgcICQoLDA0ODw\n" +
	"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n" +
	"-B5iTp-AXzAzRyRT3PzNPt9ukdY5HYIabH8Lc3Gyquk\n" +
	"33333333-3333-4333-8333-333333333333"

const goldenAppRefreshSignature = "14/swCe0gB4eM76jfKkOgRSymss546NNIypb9ttCVUWA6fGth3lZUbKLTojMtRrC48Da4PmJ5J35qU87f1BlBw=="

func storeGoldenRequestKey(t *testing.T, deps Deps) ed25519.PublicKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(goldenAppRefreshSeed)
	if err := keychain.SaveRequestSigningPrivateKey(deps.Store, base64.StdEncoding.EncodeToString(priv)); err != nil {
		t.Fatalf("save priv: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := keychain.SaveRequestSigningPublicKey(deps.Store, base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatalf("save pub: %v", err)
	}
	return pub
}

func TestAppSessionRefreshCanonical_Golden(t *testing.T) {
	got := AppSessionRefreshCanonical(goldenAppRefreshRequest())
	t.Logf("canonical:\n%s", got)
	if got != goldenAppRefreshCanonical {
		t.Fatalf("canonical drifted:\n got %q\nwant %q", got, goldenAppRefreshCanonical)
	}
}

func TestHandleSignAppSessionRefresh_GoldenSignature(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	pub := storeGoldenRequestKey(t, deps)

	resp := HandleSignAppSessionRefresh(deps, goldenAppRefreshRequest())
	if !resp.Success {
		t.Fatalf("sign: %s", resp.Error)
	}
	data := resp.Data.(proto.SignRequestResponseData)
	t.Logf("signature: %s", data.Signature)
	if data.Signature != goldenAppRefreshSignature {
		t.Fatalf("signature drifted: got %s want %s", data.Signature, goldenAppRefreshSignature)
	}
	sig, _ := base64.StdEncoding.DecodeString(data.Signature)
	if !ed25519.Verify(pub, []byte(goldenAppRefreshCanonical), sig) {
		t.Fatal("signature does not verify over the golden canonical")
	}
	for _, msg := range log.Messages() {
		if strings.Contains(msg, goldenAppRefreshRequest().AppBinding) {
			t.Errorf("app binding echoed in logs: %q", msg)
		}
	}
}

func TestHandleSignAppSessionRefresh_RefusesInvalidFields(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	storeGoldenRequestKey(t, deps)
	mutate := []func(*proto.SignAppSessionRefreshRequest){
		func(r *proto.SignAppSessionRefreshRequest) { r.Origin = "https://app.dragpass.io/" },
		func(r *proto.SignAppSessionRefreshRequest) { r.Origin = "https://app.dragpass.io\nx" },
		func(r *proto.SignAppSessionRefreshRequest) { r.Origin = "chrome-extension://abc" },
		func(r *proto.SignAppSessionRefreshRequest) { r.Timestamp = "01789000000" },
		func(r *proto.SignAppSessionRefreshRequest) { r.Nonce = "short" },
		func(r *proto.SignAppSessionRefreshRequest) { r.BodySHA256 = strings.ToUpper(r.BodySHA256) },
		func(r *proto.SignAppSessionRefreshRequest) { r.AppBinding = r.AppBinding + "\nPOST" },
		func(r *proto.SignAppSessionRefreshRequest) { r.DeviceID = "dev\nice-id-1" },
	}
	for i, m := range mutate {
		req := goldenAppRefreshRequest()
		m(&req)
		r := HandleSignAppSessionRefresh(deps, req)
		if r.Success || r.ErrorCode != string(errs.ErrCodeValidation) || r.Data != nil {
			t.Errorf("case %d: want validation_error without a signature, got %+v", i, r)
		}
	}
}

// Once the device id is stored, only a refresh naming it is signed, as for
// sign_request.
func TestHandleSignAppSessionRefresh_DeviceIDMustMatchStoredID(t *testing.T) {
	deps, _, store := newTestDeps(t)
	storeGoldenRequestKey(t, deps)

	if r := HandleSignAppSessionRefresh(deps, goldenAppRefreshRequest()); !r.Success {
		t.Fatalf("sign before a device id is stored: %s", r.Error)
	}
	ensured := HandleDeviceIDEnsure(deps, proto.DeviceIDEnsureRequest{})
	if !ensured.Success {
		t.Fatalf("ensure: %s", ensured.Error)
	}
	own := ensured.Data.(proto.DeviceIDEnsureResponseData).DeviceID

	other := goldenAppRefreshRequest()
	if r := HandleSignAppSessionRefresh(deps, other); r.Success || r.ErrorCode != string(errs.ErrCodeValidation) || r.Data != nil {
		t.Fatalf("other device: want validation_error, got %+v", r)
	}
	mine := goldenAppRefreshRequest()
	mine.DeviceID = own
	if r := HandleSignAppSessionRefresh(deps, mine); !r.Success {
		t.Fatalf("own device: %s", r.Error)
	}

	if err := store.Set(config.Service, config.DeviceID, "not-a-uuid"); err != nil {
		t.Fatalf("seed invalid id: %v", err)
	}
	if r := HandleSignAppSessionRefresh(deps, mine); r.Success || r.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("invalid stored id: want storage_failure, got %+v", r)
	}
}

func TestHandleSignAppSessionRefresh_NoActiveKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	r := HandleSignAppSessionRefresh(deps, goldenAppRefreshRequest())
	if r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("want not_found, got %+v", r)
	}
}

// sign_request signs only dp-req-v1, so the refresh domain (or any other
// string) cannot be obtained through it, with or without a stored device id.
func TestHandleSignRequest_RefusesOtherDomains(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	storeGoldenRequestKey(t, deps)
	for i, canonical := range []string{goldenAppRefreshCanonical, "post-promote"} {
		r := HandleSignRequest(deps, proto.SignRequestRequest{CanonicalRequest: canonical})
		if r.Success || r.ErrorCode != string(errs.ErrCodeValidation) || r.Data != nil {
			t.Errorf("case %d: want validation_error without a signature, got %+v", i, r)
		}
	}
}
