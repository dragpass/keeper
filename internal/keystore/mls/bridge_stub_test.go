//go:build !mls || !cgo

package mls

import (
	"errors"
	"testing"
)

// The default build has to say "no library" rather than "no group", because a
// caller that cannot tell those apart will retry the wrong one forever.
func TestDefaultBuildAnswersUnavailable(t *testing.T) {
	if Available() {
		t.Fatal("Available() is true in a build without the mls tag")
	}
	if _, err := Version(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Version() = %v; want ErrUnavailable", err)
	}
	if _, err := NewSession(nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewSession() = %v; want ErrUnavailable", err)
	}
}
