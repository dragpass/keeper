// Logger (StdLogger / MemoryLogger) aliases.
//
// Handlers and tests reference these names without the `logger.` prefix; the
// actual implementation lives in internal/keystore/logger/.

package keystore

import "github.com/dragpass/keeper/internal/keystore/logger"

type (
	Logger    = logger.Logger
	StdLogger = logger.StdLogger
)

var NewMemoryLogger = logger.NewMemoryLogger
