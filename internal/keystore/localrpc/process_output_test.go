package localrpc

import (
	"bytes"
	"sync"
)

// processOutput collects a child Keeper's stderr. os/exec copies the child's
// output from its own goroutine while a test reads what arrived so far, so
// the buffer is guarded; a bare bytes.Buffer there is a data race in the test
// harness that -race reports.
type processOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *processOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *processOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *processOutput) Bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.buf.Bytes())
}
