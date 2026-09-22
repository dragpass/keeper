//go:build windows

// The Unix build states "only the owner may read this" as mode 0600. Windows
// has no such bit, so the same property is asserted through the mechanism
// Windows actually enforces: the file's DACL must hold exactly one
// access-allowed entry, it must name this process's user, and it must be
// protected so nothing is inherited from the parent directory.
//
// This is deliberately not a skip. A skip here would report green while the
// released dragpass-keeper.exe wrote state files anyone on the machine could
// read.

package chatstate

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertOwnerOnlyAccess(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read the security descriptor of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read the descriptor control bits: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL is not protected, so the parent directory's entries still apply")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("the file has a null DACL, which grants everyone full access")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("the DACL holds %d entries, want exactly 1 for the owner", dacl.AceCount)
	}

	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("read the only ACE: %v", err)
	}
	granted := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("resolve the current user: %v", err)
	}
	if !granted.Equals(user.User.Sid) {
		t.Fatalf("the DACL grants %s, want the current user %s", granted, user.User.Sid)
	}
}
