// Sessions (GroupSessionStore + RecoverySessionStore) aliases.
//
// Handlers reference these names without the `sessions.` prefix; the actual
// implementation lives in internal/keystore/sessions/.

package keystore

import "github.com/dragpass/keeper/internal/keystore/sessions"

var (
	NewGroupSessionStore              = sessions.NewGroupSessionStore
	StartDefaultGroupSessionReaper    = sessions.StartDefaultGroupSessionReaper
	StartDefaultRecoverySessionReaper = sessions.StartDefaultRecoverySessionReaper
)
