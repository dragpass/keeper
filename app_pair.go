package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

// printAppPairingLink prints the link that pairs a browser's DragPass App with
// this user's Keeper. The key rides in the URL fragment, which the browser
// never sends to a server. It is the App pairing key, not the root secret.
func printAppPairingLink(args []string) error {
	flags := flag.NewFlagSet("app pair", flag.ContinueOnError)
	origin := flags.String("origin", "https://app.dragpass.io", "App origin to pair")
	if err := flags.Parse(args); err != nil {
		return err
	}
	link, err := appPairingLink(*origin)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Open this link in the browser where you use the DragPass app:")
	fmt.Fprintln(os.Stdout, link)
	return nil
}

func appPairingLink(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1") {
		return "", errors.New("App origin must be an https origin (or a localhost dev origin)")
	}
	secret, err := localsecret.LoadOrCreate()
	if err != nil {
		return "", fmt.Errorf("load Keeper local secret: %w", err)
	}
	return origin + "/#keeper-pair=" + base64.RawURLEncoding.EncodeToString(secret.AppPairingKey()), nil
}
