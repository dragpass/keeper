package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/dragpass/keeper/internal/keystore/localsecret"
)

const defaultAppOrigin = "https://app.dragpass.io"

const pairingPageName = "pair.html"

// runAppCommand handles `dragpass-keeper app pair|rotate-secret`.
func runAppCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dragpass-keeper app pair|rotate-secret [--origin URL] [--no-open]")
	}
	flags := flag.NewFlagSet("app "+args[0], flag.ContinueOnError)
	origin := flags.String("origin", defaultAppOrigin, "App origin to pair")
	noOpen := flags.Bool("no-open", false, "print the pairing link instead of opening it in the browser")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "pair":
		return pairApp(*origin, !*noOpen, out)
	case "rotate-secret":
		if _, err := localsecret.Rotate(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Keeper local secret rotated. Every browser paired before is no longer paired.")
		return pairApp(*origin, !*noOpen, out)
	default:
		return errors.New("usage: dragpass-keeper app pair|rotate-secret [--origin URL] [--no-open]")
	}
}

// pairApp opens, or prints, the link that pairs a browser's DragPass App with
// this user's Keeper. The key rides in the URL fragment, which the browser
// never sends to a server. It is the App pairing key, not the root secret.
func pairApp(origin string, open bool, out io.Writer) error {
	link, err := appPairingLink(origin)
	if err != nil {
		return err
	}
	if !open {
		fmt.Fprintln(out, "Open this link in the browser where you use the DragPass app:")
		fmt.Fprintln(out, link)
		return nil
	}
	if err := openPairingLink(link); err != nil {
		// The link is not printed here: this also runs from `service install`,
		// whose output an installer may keep in a log.
		fmt.Fprintf(out, "Could not open the browser (%v). Run `dragpass-keeper app pair --no-open` in your own terminal and open the link it prints.\n", err)
		return nil
	}
	fmt.Fprintln(out, "The pairing page opened in your default browser. If it opened in the wrong browser, run `dragpass-keeper app pair --no-open` and open the link where you use the DragPass app.")
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

// openPairingLink hands the browser an owner-only local page that redirects
// to the link. Passing the link itself to `open` / `xdg-open` would put the
// pairing key in a process argument list, which other OS users can read: the
// very users pairing exists to keep out. The page sits next to the secret it
// is derived from, so it exposes nothing that directory does not already hold.
func openPairingLink(link string) error {
	dir, err := localsecret.Dir()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(link)
	if err != nil {
		return err
	}
	page := "<!doctype html><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">" +
		"<title>DragPass Keeper</title><script>location.replace(" + string(encoded) + ")</script>"
	path := filepath.Join(dir, pairingPageName)
	temp, err := os.CreateTemp(dir, ".pair-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.WriteString(page)
	chmodErr := temp.Chmod(0o600)
	closeErr := temp.Close()
	if writeErr != nil || chmodErr != nil || closeErr != nil {
		return errors.New("write the pairing page")
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return err
	}
	return openInBrowser(path)
}

var openInBrowser = func(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		return errors.New("no default browser opener on this operating system")
	}
	return cmd.Run()
}
