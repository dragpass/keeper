// sink.go — which clipboard backend a process should use.
//
// The decision is a pure function of two booleans so it can be unit tested
// without constructing either backend (NewProductionClipboard calls
// osclip.Init, which touches the developer's pasteboard on macOS and fails
// asymmetrically on headless Linux CI — see app.go's testing.Testing()
// carve-out for the same reasoning).

package clipboard

// Sink names the clipboard backend a process should use.
type Sink int

const (
	// SinkOS is the real OS clipboard — the production backend.
	SinkOS Sink = iota
	// SinkMemory is the in-process fake KEEPER_E2E_MODE uses by default, so
	// tests never touch the developer's pasteboard and
	// `clipboard_get_last_hash` has a hash to report.
	SinkMemory
)

// E2EOSClipboardEnvVar opts an e2e-mode process back into the real OS
// clipboard.
//
// **Honored only when KEEPER_E2E_MODE=1.** Outside e2e mode the OS clipboard
// is already the sink, so the variable is a no-op there and cannot weaken a
// production process.
//
// The one caller is the marketing hero recorder
// (dragpass `tests/e2e-extension/recordings/record-hero.ts`): the recorded
// scene needs the content script's `navigator.clipboard.readText()` to
// actually see the decrypted plaintext, which MemoryClipboard cannot deliver.
// The cost is `clipboard_get_last_hash`, which requires MemoryClipboard and
// therefore returns ErrCodeUnsupported while this flag is set.
const E2EOSClipboardEnvVar = "KEEPER_E2E_OS_CLIPBOARD"

// SelectSink resolves the clipboard backend from the two e2e switches.
//
// Matrix:
//
//	e2eMode=false, optIn=any   → SinkOS     (production; optIn ignored)
//	e2eMode=true,  optIn=false → SinkMemory (default e2e)
//	e2eMode=true,  optIn=true  → SinkOS     (recording opt-in)
func SelectSink(e2eMode, e2eOSClipboardOptIn bool) Sink {
	if e2eMode && !e2eOSClipboardOptIn {
		return SinkMemory
	}
	return SinkOS
}
