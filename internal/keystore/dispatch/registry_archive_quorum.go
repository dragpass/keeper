// registry_archive_quorum.go — archive-key admin quorum action registrations.
//
// Mirrors proto/actions_archive_quorum.go: the Shamir N-of-M break-glass flow
// (split, per-admin share rewrap, recovery-session lifecycle, and the
// combine + re-grant composite).

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
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
		proto.ActionArchiveSessionBegin:           archiveLoginAction(handlers.HandleArchiveSessionBegin).appOnlyAction(),
		proto.ActionArchiveSessionSetExpiry:       archiveLoginAction(handlers.HandleArchiveSessionSetExpiry).appOnlyAction(),
		proto.ActionArchiveSessionEnd:             archiveLoginAction(handlers.HandleArchiveSessionEnd).appOnlyAction(),
		proto.ActionArchiveSessionLegacyDiscard:   archiveLoginAction(handlers.HandleArchiveSessionLegacyDiscard).appOnlyAction(),
		proto.ActionArchiveSessionDiscard:         archiveLoginAction(handlers.HandleArchiveSessionDiscard).appOnlyAction(),
		proto.ActionArchiveSessionStatus:          archiveLoginAction(handlers.HandleArchiveSessionStatus).appOnlyAction(),
		proto.ActionArchiveQuorumCombineAndRewrap: archiveLoginAction(handlers.HandleArchiveQuorumCombineAndRewrap).appOnlyAction(),
		proto.ActionArchiveReconfigureStage:       archiveLoginAction(handlers.HandleArchiveReconfigureStage).appOnlyAction(),
	}
}

func archiveLoginAction[T interface {
	InitiatingArchiveLogin() proto.ArchiveLoginIdentity
}](handler func(handlers.Deps, T) proto.BaseResponse) action {
	return wrap(func(d handlers.Deps, req T) proto.BaseResponse {
		login := req.InitiatingArchiveLogin()
		if err := login.Validate(); err != nil {
			return errs.Response(err)
		}
		d.ArchiveRequestLogin = &login
		return handler(d, req)
	})
}
