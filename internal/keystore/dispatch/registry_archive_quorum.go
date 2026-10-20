// registry_archive_quorum.go — archive-key admin quorum action registrations.
//
// Mirrors proto/actions_archive_quorum.go: the Shamir N-of-M break-glass flow
// (split, per-admin share rewrap, recovery-session lifecycle, and the
// combine + re-grant composite).

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// App-only: the break-glass quorum runs in the App's organization console.
func archiveQuorumActions() map[string]action {
	return map[string]action{
		proto.ActionArchiveKeySplit:               wrap(handlers.HandleArchiveKeySplit).appOnlyAction(),
		proto.ActionArchiveShareRewrap:            wrap(handlers.HandleArchiveShareRewrap).appOnlyAction(),
		proto.ActionArchiveSessionBegin:           wrap(handlers.HandleArchiveSessionBegin).appOnlyAction(),
		proto.ActionArchiveSessionEnd:             wrap(handlers.HandleArchiveSessionEnd).appOnlyAction(),
		proto.ActionArchiveQuorumCombineAndRewrap: wrap(handlers.HandleArchiveQuorumCombineAndRewrap).appOnlyAction(),
	}
}
