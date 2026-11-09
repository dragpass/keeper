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
		proto.ActionArchiveSplitPrepare:           wrapCapped(proto.DEKRewrapMaxRequestBytes, handlers.HandleArchiveSplitPrepare).appOnlyAction(),
		proto.ActionArchiveSharePrepare:           wrapCapped(proto.DEKRewrapMaxRequestBytes, handlers.HandleArchiveSharePrepare).appOnlyAction(),
		proto.ActionArchiveShareRewrap:            wrap(handlers.HandleArchiveShareRewrap).appOnlyAction(),
		proto.ActionArchiveShareProofPrepare:      wrapCapped(proto.DEKRewrapMaxRequestBytes, handlers.HandleArchiveShareProofPrepare).appOnlyAction(),
		proto.ActionArchiveShareOpenProof:         wrapCapped(proto.DEKRewrapMaxRequestBytes, handlers.HandleArchiveShareOpenProof).appOnlyAction(),
		proto.ActionArchiveSplitStatus:            wrap(handlers.HandleArchiveSplitStatus).appOnlyAction(),
		proto.ActionArchiveSplitFinalize:          wrap(handlers.HandleArchiveSplitFinalize).appOnlyAction(),
		proto.ActionArchiveSplitAbandon:           wrap(handlers.HandleArchiveSplitAbandon).appOnlyAction(),
		proto.ActionArchiveSessionBegin:           wrap(handlers.HandleArchiveSessionBegin).appOnlyAction(),
		proto.ActionArchiveSessionEnd:             wrap(handlers.HandleArchiveSessionEnd).appOnlyAction(),
		proto.ActionArchiveQuorumCombineAndRewrap: wrap(handlers.HandleArchiveQuorumCombineAndRewrap).appOnlyAction(),
	}
}
