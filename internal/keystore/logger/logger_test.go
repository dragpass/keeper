// Unit tests for logger.go.
//
// **Defects this test catches:**
//   - Regressions where MemoryLogger drops Println / Printf messages
//   - Regressions where Messages exposes the internal slice directly, causing
//     caller mutation to race with logger writes
//   - Regressions where Contains substring matching is inaccurate
//   - Regressions where old messages persist after Reset
package logger

import "testing"

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

func TestStdLogger_DoesNotPanic(t *testing.T) {
	// The production logger delegates to stdlib log — as long as the call
	// does not panic it is OK. stderr capture is the responsibility of a
	// different layer's tests.
	l := StdLogger{}
	l.Println("std logger smoke")
	l.Printf("%s=%d", "smoke", 1)
}
