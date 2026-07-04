// Package logger — Logger: structured-log abstraction.
//
// **DI motivation:** keeper handlers call `log.Println` / `log.Printf`
// directly. For unit tests to assert "this handler did not leave sensitive
// values in the log," they would have to capture stderr / stdout and inspect
// it with regex — that has high coupling and is process-global, which breaks
// parallel testing.
//
// Introducing a Logger interface allows:
//
//   - tests to inject MemoryLogger and collect messages into an isolated slice.
//   - expressing "the secret was not echoed into the log" regression guards
//     as assertions.
//   - swapping to a structured logger (zerolog/slog) later by changing only
//     one place.
//
// **Current phase scope:** define the Logger interface + StdLogger /
// MemoryLogger + expose the App.Logger field. Migration of the 167+ log.*
// calls in handlers is staged in follow-up phases — this phase only adds
// the wiring infrastructure.
package logger

import (
	"fmt"
	"log"
	"sync"
)

// Logger is the minimal log contract used by keeper handlers.
// Its signatures match Println/Printf from the stdlib `log` package so
// callers can swap `log.Println(...)` for `app.Logger.Println(...)`
// near-mechanically.
type Logger interface {
	Println(args ...any)
	Printf(format string, args ...any)
}

// StdLogger is for production — it delegates directly to the stdlib `log`
// package, so output is identical to direct log.Println / log.Printf calls.
type StdLogger struct{}

func (StdLogger) Println(args ...any) {
	log.Println(args...)
}

func (StdLogger) Printf(format string, args ...any) {
	log.Printf(format, args...)
}

// MemoryLogger is for unit tests — it keeps all messages in a slice so that
// regression guards like "the secret was not echoed into the log" can be
// expressed as assertions.
//
// `mu` is intentionally a plain sync.Mutex — tests call a handler once and
// then inspect, so RWMutex would be overkill.
type MemoryLogger struct {
	mu       sync.Mutex
	messages []string
}

// NewMemoryLogger creates a logger with an empty capture slice.
func NewMemoryLogger() *MemoryLogger {
	return &MemoryLogger{messages: make([]string, 0, 8)}
}

func (m *MemoryLogger) Println(args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintln(args...))
}

func (m *MemoryLogger) Printf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintf(format, args...))
}

// Messages returns a copy of the captured message slice.
// Mutating the returned slice is safe with respect to logger internal state.
func (m *MemoryLogger) Messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.messages))
	copy(out, m.messages)
	return out
}

// Contains returns true if any captured message contains substr.
// Provided for unit-test assertion convenience.
func (m *MemoryLogger) Contains(substr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, msg := range m.messages {
		if containsSubstr(msg, substr) {
			return true
		}
	}
	return false
}

// containsSubstr — kept simple to avoid an extra strings package import.
// Returns true for an empty substr (same semantics as Go strings.Contains).
func containsSubstr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Reset clears all captured messages. Useful when reusing the same logger
// across multiple sub-tests.
func (m *MemoryLogger) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = m.messages[:0]
}
