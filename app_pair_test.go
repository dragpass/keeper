package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
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

func captureBrowser(t *testing.T) *[]string {
	t.Helper()
	opened := &[]string{}
	previous := openInBrowser
	openInBrowser = func(path string) error {
		*opened = append(*opened, path)
		return nil
	}
	t.Cleanup(func() { openInBrowser = previous })
	return opened
}

func pairingKeyB64(t *testing.T) string {
	t.Helper()
	secret, err := localsecret.Load()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(secret.AppPairingKey())
}

func TestAppPairOpensTheLinkWithoutPuttingTheKeyInProcessArguments(t *testing.T) {
	t.Setenv(localsecret.DirEnvVar, filepath.Join(t.TempDir(), "local"))
	opened := captureBrowser(t)
	var out bytes.Buffer
	if err := runAppCommand([]string{"pair"}, &out); err != nil {
		t.Fatal(err)
	}
	key := pairingKeyB64(t)
	if len(*opened) != 1 || strings.Contains((*opened)[0], key) {
		t.Fatalf("browser opener got %q; the key must not be an argument", *opened)
	}
	if strings.Contains(out.String(), key) {
		t.Fatalf("pair printed the key while opening the browser: %s", out.String())
	}
	page, err := os.ReadFile((*opened)[0])
	if err != nil || !strings.Contains(string(page), "https://app.dragpass.io/#keeper-pair="+key) {
		t.Fatalf("pairing page = %q, %v", page, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat((*opened)[0]); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("pairing page mode = %v, %v", info, err)
		}
	}

	out.Reset()
	if err := runAppCommand([]string{"pair", "--no-open"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(*opened) != 1 || !strings.Contains(out.String(), "#keeper-pair="+key) {
		t.Fatalf("--no-open must print the link and open nothing: opened=%q out=%s", *opened, out.String())
	}
}

func TestAppRotateSecretIssuesANewPairingKey(t *testing.T) {
	t.Setenv(localsecret.DirEnvVar, filepath.Join(t.TempDir(), "local"))
	captureBrowser(t)
	var out bytes.Buffer
	if err := runAppCommand([]string{"rotate-secret", "--no-open"}, &out); err == nil {
		t.Fatal("rotated a secret that was never created")
	}
	if err := runAppCommand([]string{"pair"}, &out); err != nil {
		t.Fatal(err)
	}
	before := pairingKeyB64(t)
	out.Reset()
	if err := runAppCommand([]string{"rotate-secret", "--no-open"}, &out); err != nil {
		t.Fatal(err)
	}
	after := pairingKeyB64(t)
	if before == after || strings.Contains(out.String(), before) || !strings.Contains(out.String(), "#keeper-pair="+after) {
		t.Fatalf("rotation did not issue a new pairing key: %s", out.String())
	}
	if err := runAppCommand([]string{"unknown"}, &out); err == nil {
		t.Fatal("accepted an unknown app command")
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
