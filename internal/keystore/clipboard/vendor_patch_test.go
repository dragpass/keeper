package clipboard

import (
	"bytes"
	"os"
	"testing"
)

// TestVendoredClipboardOpensLibX11Soname guards the local patch in the
// vendored golang.design/x/clipboard. `go mod vendor` rewrites the file from
// the module cache and drops the patch without a word, and the failure it
// brings back shows only on a Linux desktop without libx11-dev, where
// decrypt-to-clipboard stops working.
func TestVendoredClipboardOpensLibX11Soname(t *testing.T) {
	src, err := os.ReadFile("../../../vendor/golang.design/x/clipboard/clipboard_linux.c")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`dlopen("libX11.so.6", RTLD_LAZY)`)) {
		t.Fatal(`vendored clipboard_linux.c lost the local patch that opens "libX11.so.6"; reapply it`)
	}
}
