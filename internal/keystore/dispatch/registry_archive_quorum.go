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

func archiveQuorumActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		proto.ActionArchiveKeySplit:               wrap(handlers.HandleArchiveKeySplit),
		proto.ActionArchiveShareRewrap:            wrap(handlers.HandleArchiveShareRewrap),
		proto.ActionArchiveSessionBegin:           wrap(handlers.HandleArchiveSessionBegin),
		proto.ActionArchiveSessionEnd:             wrap(handlers.HandleArchiveSessionEnd),
		proto.ActionArchiveQuorumCombineAndRewrap: wrap(handlers.HandleArchiveQuorumCombineAndRewrap),
	}
}
