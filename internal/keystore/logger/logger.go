// Package logger provides injectable logging. Tests inject
// testdouble.MemoryLogger to assert that secrets are not logged.
package logger

import "log"

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
