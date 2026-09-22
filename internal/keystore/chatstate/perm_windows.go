//go:build windows

// perm_windows.go — the Windows half of "only this user may read the state".
//
// Windows does not honor the Unix mode bits os.Chmod takes: the 0o600 the rest
// of this package asks for arrives as 0666, and a state file otherwise carries
// whatever ACEs it inherits from the parent directory. ADR S4 makes "the files
// alone are worthless" a requirement rather than a convenience, and the
// released dragpass-keeper.exe is a real target, so the property is rebuilt
// here out of what Windows does enforce: a DACL holding exactly one
// access-allowed entry for the token user, applied with
// PROTECTED_DACL_SECURITY_INFORMATION so no inherited entry survives on the
// object.
//
// **Be exact about what this buys.** It keeps other users of the machine out of
// the state directory, which is what the Unix mode bit buys and no more. It
// does not separate processes running as the same user: they can read the file,
// and they can read the seal key out of Credential Manager as well. The file
// boundary is not a cryptographic boundary on either platform (ADR §3.3). The
// owner of a file also keeps implicit WRITE_DAC, so same-user code can undo
// this — which is the same statement, said from the other side.

package chatstate

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func restrictFileToOwner(path string) error {
	return applyOwnerOnlyDACL(path, windows.NO_INHERITANCE)
}

// restrictDirToOwner also marks the entry inheritable, so a lock or temp file
// created in the directory later starts owner-only instead of relying on the
// process's default DACL. Record files do not depend on that: they are
// restricted explicitly and protected from inheritance.
func restrictDirToOwner(path string) error {
	return applyOwnerOnlyDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func applyOwnerOnlyDACL(path string, inheritance uint32) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve the current user: %w", err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build the owner-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("restrict %s to its owner: %w", path, err)
	}
	return nil
}
