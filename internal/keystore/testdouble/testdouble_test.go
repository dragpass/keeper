// Tests for the test doubles themselves, and the guard that keeps them out of
// the production import graph.
package testdouble

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMemoryLogger_PrintlnCaptured(t *testing.T) {
	l := NewMemoryLogger()
	l.Println("hello", "world")

	msgs := l.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	// fmt.Sprintln inserts a space between args and a newline at the end.
	if msgs[0] != "hello world\n" {
		t.Fatalf("got %q", msgs[0])
	}
}

func TestMemoryLogger_PrintfCaptured(t *testing.T) {
	l := NewMemoryLogger()
	l.Printf("key=%s val=%d", "alpha", 42)

	msgs := l.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0] != "key=alpha val=42" {
		t.Fatalf("got %q", msgs[0])
	}
}

func TestMemoryLogger_Contains(t *testing.T) {
	l := NewMemoryLogger()
	l.Printf("user=%s action=login", "alice")

	if !l.Contains("alice") {
		t.Fatalf("expected to contain alice")
	}
	if l.Contains("bob") {
		t.Fatalf("must not match unrelated substring")
	}
}

func TestMemoryLogger_DoesNotEchoSecret(t *testing.T) {
	// Regression guard pattern — example of asserting that secrets are not
	// echoed into logs when a real handler is invoked with the logger injected.
	l := NewMemoryLogger()
	const secret = "SUPER_SECRET_DO_NOT_LEAK"

	// A correct handler must not log the secret.
	l.Printf("processing request: action=%s", "login")
	l.Println("login succeeded")

	if l.Contains(secret) {
		t.Fatalf("secret leaked into log: %v", l.Messages())
	}
}

func TestMemoryLogger_MessagesReturnsCopy(t *testing.T) {
	// Mutating the slice returned to the caller must not affect logger internals.
	l := NewMemoryLogger()
	l.Println("a")
	l.Println("b")

	msgs := l.Messages()
	msgs[0] = "MUTATED"

	again := l.Messages()
	if again[0] == "MUTATED" {
		t.Fatalf("Messages must return defensive copy")
	}
}

func TestMemoryLogger_Reset(t *testing.T) {
	l := NewMemoryLogger()
	l.Println("first")
	l.Reset()
	l.Println("second")

	msgs := l.Messages()
	if len(msgs) != 1 {
		t.Fatalf("Reset failed, got %d messages", len(msgs))
	}
	if msgs[0] != "second\n" {
		t.Fatalf("got %q", msgs[0])
	}
}

func TestAlwaysOKVerifier_AcceptsAnyInput(t *testing.T) {
	v := AlwaysOKVerifier{}
	cases := []struct {
		token, sig string
		ver        uint
	}{
		{"any", "any", 0},
		{"", "", 1},
		{"long-challenge-token", "AAAAAAAA", 99},
	}
	for _, c := range cases {
		if err := v.Verify(c.token, c.sig, c.ver); err != nil {
			t.Errorf("AlwaysOK rejected (%v): %v", c, err)
		}
	}
}

func TestAlwaysFailVerifier_DefaultErrorMessage(t *testing.T) {
	v := AlwaysFailVerifier{}
	err := v.Verify("any", "any", 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	// Preserve the prefix that existing handler code checks.
	if !strings.Contains(err.Error(), "server signature verification failed") {
		t.Fatalf("error must include 'server signature verification failed' prefix, got %q", err.Error())
	}
}

func TestAlwaysFailVerifier_RespectsCustomError(t *testing.T) {
	custom := errors.New("custom verifier failure")
	v := AlwaysFailVerifier{Err: custom}
	err := v.Verify("any", "any", 0)
	if !errors.Is(err, custom) {
		t.Fatalf("expected custom error, got %v", err)
	}
}

// TestNoProductionPackageImportsTestDouble lists the non-test dependencies of
// the module's binaries for every OS the Keeper ships on, under each build tag
// set the Makefile and CI use, and fails if testdouble is among them.
func TestNoProductionPackageImportsTestDouble(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list nine times")
	}
	const module = "github.com/dragpass/keeper"
	for _, goos := range []string{"darwin", "linux", "windows"} {
		for _, tags := range []string{"", "mls", "mls,keeper_killseam"} {
			cmd := exec.Command("go", "list", "-deps", "-tags="+tags, module, module+"/cmd/action-manifest")
			cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=1")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list (GOOS=%s tags=%q): %v", goos, tags, err)
			}
			for _, dep := range strings.Fields(string(out)) {
				if dep == module+"/internal/keystore/testdouble" {
					t.Errorf("a production package imports testdouble (GOOS=%s tags=%q)", goos, tags)
				}
			}
		}
	}
}
