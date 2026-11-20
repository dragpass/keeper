package keystore

import (
	"context"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// The process sweeper stops with its context; the interval is long enough
// that no tick fires during the test.
func TestStartArchiveSessionSweeperStopsWithItsContext(t *testing.T) {
	app := NewApp(Deps{Store: testdouble.NewMemorySecretStore()})
	ctx, cancel := context.WithCancel(context.Background())
	done := app.StartArchiveSessionSweeper(ctx, time.Hour)
	select {
	case <-done:
		t.Fatal("the sweeper stopped before its context ended")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweeper did not stop with its context")
	}
}
