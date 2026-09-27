package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

func TestAppPairingLinkCarriesOnlyThePairingKeyInTheFragment(t *testing.T) {
	t.Setenv(localsecret.DirEnvVar, t.TempDir())
	link, err := appPairingLink("https://app.dragpass.io")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := localsecret.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := "https://app.dragpass.io/#keeper-pair=" + base64.RawURLEncoding.EncodeToString(secret.AppPairingKey())
	if link != want {
		t.Fatalf("link = %q, want %q", link, want)
	}
	if strings.Contains(link, base64.RawURLEncoding.EncodeToString(secret.NativeProxyKey())) {
		t.Fatal("pairing link leaks the native proxy key")
	}
	for _, origin := range []string{"http://evil.example", "https://app.dragpass.io/path", "https://app.dragpass.io?x=1", "not a url"} {
		if _, err := appPairingLink(origin); err == nil {
			t.Fatalf("accepted origin %q", origin)
		}
	}
	if _, err := appPairingLink("http://localhost:5174"); err != nil {
		t.Fatalf("dev origin refused: %v", err)
	}
}

func TestE2EModeKeepsOffTheSharedLocalAddressUnlessIsolated(t *testing.T) {
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	if !localRPCEnabled(getenv) {
		t.Fatal("production Keeper must take part in the shared local owner")
	}
	env[e2eEnvVar] = "1"
	if localRPCEnabled(getenv) {
		t.Fatal("an e2e Keeper with a mock keyring must not proxy to or serve the real local address")
	}
	env[localsecret.DirEnvVar] = t.TempDir()
	if !localRPCEnabled(getenv) {
		t.Fatal("an e2e Keeper with an isolated local secret may use local RPC")
	}
}
