// registry_archive.go — org / account archive keypair action registrations.
//
// Mirrors proto/actions_archive.go: per-org and per-account Archive / Recovery
// keypairs, same-device archive-key rotation, and the break-glass re-grant
// composite. The Shamir N-of-M quorum actions live in registry_archive_quorum.go.

package dispatch

import (
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func archiveActions() map[string]actionHandlerFunc {
	return map[string]actionHandlerFunc{
		// per-org Archive / Recovery keypair actions
		proto.ActionArchiveKeyGenerate:     wrap(handlers.HandleArchiveKeyGenerate),
		proto.ActionArchiveKeyStatus:       wrap(handlers.HandleArchiveKeyStatus),
		proto.ActionArchiveUnwrapAndRewrap: wrap(handlers.HandleArchiveUnwrapAndRewrap),

		// same-device org archive key rotation (staging-slot pattern)
		proto.ActionArchiveKeyRotateBegin:  wrap(handlers.HandleArchiveKeyRotateBegin),
		proto.ActionArchiveKeyRotateCommit: wrap(handlers.HandleArchiveKeyRotateCommit),
		proto.ActionArchiveKeyRotateAbort:  wrap(handlers.HandleArchiveKeyRotateAbort),

		// per-account Archive / Recovery receiving keypair actions
		proto.ActionAccountArchiveKeyGenerate: wrap(handlers.HandleAccountArchiveKeyGenerate),
		proto.ActionAccountArchiveKeyStatus:   wrap(handlers.HandleAccountArchiveKeyStatus),
	}
}
