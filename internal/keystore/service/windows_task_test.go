package service

import (
	"strings"
	"testing"
)

func TestScheduledTaskCommandQuotesProgramAndTrustFile(t *testing.T) {
	command := renderScheduledTaskCommand(`C:\Program Files\DragPass & Co\dragpass-keeper.exe`, `C:\Users\test\Key Transparency\trust.json`)
	if !strings.Contains(command, `"C:\Program Files\DragPass & Co\dragpass-keeper.exe" --app-service`) {
		t.Fatalf("executable path was not quoted: %s", command)
	}
	if !strings.HasSuffix(command, `--key-transparency-trust-file "C:\Users\test\Key Transparency\trust.json"`) {
		t.Fatalf("trust file path was not quoted: %s", command)
	}
}
