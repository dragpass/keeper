package clipboard

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	osclip "golang.design/x/clipboard"
)

const productionClipboardE2EEnv = "DRAGPASS_KEEPER_CLIPBOARD_E2E"

func requireProductionClipboardE2E(t *testing.T) *OSClipboard {
	t.Helper()
	if os.Getenv(productionClipboardE2EEnv) != "1" {
		t.Skipf("set %s=1 to run OS clipboard production smoke/e2e", productionClipboardE2EEnv)
	}

	cb, ok := NewProductionClipboard().(*OSClipboard)
	if !ok {
		t.Skipf("OS clipboard unavailable: %v", productionInitErr)
	}

	original := append([]byte(nil), osclip.Read(osclip.FmtText)...)
	t.Cleanup(func() {
		osclip.Write(osclip.FmtText, original)
	})

	return cb
}

func waitForClipboardText(t *testing.T, want []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got := osclip.Read(osclip.FmtText)
		if bytes.Equal(got, want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("clipboard text did not become %q within %s; got %q", want, timeout, osclip.Read(osclip.FmtText))
}

func waitForClipboardNotText(t *testing.T, notWant []byte, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got := osclip.Read(osclip.FmtText)
		if !bytes.Equal(got, notWant) {
			return got
		}
		time.Sleep(25 * time.Millisecond)
	}
	got := osclip.Read(osclip.FmtText)
	t.Fatalf("clipboard text remained %q after %s", got, timeout)
	return nil
}

// productionSmokeTTL is a TTL chosen wide enough for the sentinel observation
// window between OS clipboard write propagation and scheduleClear. Some
// backends (e.g. macOS NSPasteboard) take tens to hundreds of ms to propagate
// asynchronously, so ~100ms TTLs are flaky.
const productionSmokeTTL = 500 * time.Millisecond

func TestOSClipboard_ProductionSmoke_WriteAndTTLClear(t *testing.T) {
	cb := requireProductionClipboardE2E(t)

	plaintext := []byte(fmt.Sprintf("dragpass-keeper-clipboard-e2e-clear-%d", time.Now().UnixNano()))
	if err := cb.Write(plaintext, productionSmokeTTL); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitForClipboardText(t, plaintext, time.Second)
	got := waitForClipboardNotText(t, plaintext, 2*time.Second)
	if len(got) != 0 {
		t.Fatalf("clipboard should be empty after TTL clear, got %q", got)
	}
}

func TestOSClipboard_ProductionSmoke_DoesNotClearUserReplacement(t *testing.T) {
	cb := requireProductionClipboardE2E(t)

	plaintext := []byte(fmt.Sprintf("dragpass-keeper-clipboard-e2e-original-%d", time.Now().UnixNano()))
	replacement := []byte(fmt.Sprintf("dragpass-keeper-clipboard-e2e-user-copy-%d", time.Now().UnixNano()))

	if err := cb.Write(plaintext, productionSmokeTTL); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitForClipboardText(t, plaintext, time.Second)

	osclip.Write(osclip.FmtText, replacement)
	waitForClipboardText(t, replacement, time.Second)

	time.Sleep(productionSmokeTTL + 200*time.Millisecond)
	got := osclip.Read(osclip.FmtText)
	if !bytes.Equal(got, replacement) {
		t.Fatalf("TTL clear must not erase user replacement; got %q, want %q", got, replacement)
	}
}
