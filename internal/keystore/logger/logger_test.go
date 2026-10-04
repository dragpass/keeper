// Unit tests for logger.go. MemoryLogger's tests moved with it to
// internal/keystore/testdouble.
package logger

import "testing"

func TestStdLogger_DoesNotPanic(t *testing.T) {
	// The production logger delegates to stdlib log — as long as the call
	// does not panic it is OK. stderr capture is the responsibility of a
	// different layer's tests.
	l := StdLogger{}
	l.Println("std logger smoke")
	l.Printf("%s=%d", "smoke", 1)
}
