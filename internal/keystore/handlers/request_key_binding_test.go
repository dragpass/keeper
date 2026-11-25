package handlers

import (
	"encoding/base64"
	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestRequestKeyBindingSignsTheCurrentKeeperIdentity(t *testing.T) {
	c := newRecoveryProofCase(t)
	accountPub, _ := setupHandlerKeyPair(t, c.store)
	request := proto.ArchiveLoginScope{AppLogin: *c.deps.ArchiveRequestLogin}
	response := HandleRequestKeyBinding(c.deps, request)
	if !response.Success {
		t.Fatal(response.ErrorCode)
	}
	data := response.Data.(proto.RequestKeyBinding)
	canonical := "dragpass.request-key-binding|1|" + slotTestAccount + "|" + splitTestDevice + "|ed25519|" + data.PublicKey
	pub, err := crypto.ParsePublicKey(accountPub)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(data.AccountBindingSignature)
	if err != nil || crypto.VerifySignature(pub, canonical, signature) != nil {
		t.Fatal("account binding did not verify")
	}
	if data.DeviceID != splitTestDevice || data.AccountID != slotTestAccount {
		t.Fatal("wrong identity returned")
	}
	request.AppLogin.Generation = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if got := HandleRequestKeyBinding(c.deps, request); got.Success || got.Data != nil {
		t.Fatal("stale login signed a binding")
	}
}

func TestMonitorRecognizesThisDevicesRequestKeyBinding(t *testing.T) {
	c := newRecoveryProofCase(t)
	accountPub, _ := setupHandlerKeyPair(t, c.store)
	response := HandleRequestKeyBinding(c.deps, proto.ArchiveLoginScope{AppLogin: *c.deps.ArchiveRequestLogin})
	if !response.Success {
		t.Fatal(response.ErrorCode)
	}
	binding := response.Data.(proto.RequestKeyBinding)
	payload, err := binding.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(binding.AccountBindingSignature)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := keytransparency.EncodeStatement(keytransparency.StatementDeviceRequestKeyBinding, []byte(payload), []byte(accountPub), sig)
	if err != nil {
		t.Fatal(err)
	}
	evidence, trust := signedStatementEvidence(t, statement)
	c.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	request := proto.KeyTransparencyMonitorRequest{AccountID: binding.AccountID, Events: []proto.KeyTransparencyMonitorEventRequest{{
		EventID: "00000000-0000-4000-8000-000000000002", SourceType: keytransparency.StatementDeviceRequestKeyBinding, Evidence: evidence,
	}}}
	check := func(want bool) {
		t.Helper()
		res := HandleKeyTransparencyMonitor(c.deps, request)
		if !res.Success {
			t.Fatal(res.ErrorCode)
		}
		if res.Data.(proto.KeyTransparencyMonitorResponse).Events[0].KnownOnThisDevice != want {
			t.Fatalf("known on this device, want %t", want)
		}
	}
	check(true)
	if err := c.store.Set(config.Service, config.DeviceID, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	check(false)
}
