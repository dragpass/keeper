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

// The organization console runs in the App, so every archive action but
// archive_key_generate is App-only. archive_key_generate stays on Native
// Messaging for the Extension's E2E org fixture.
func archiveActions() map[string]action {
	return map[string]action{
		// per-org Archive / Recovery keypair actions
		proto.ActionArchiveKeyGenerate:     wrap(handlers.HandleArchiveKeyGenerate),
		proto.ActionArchiveKeyStatus:       wrap(handlers.HandleArchiveKeyStatus).appOnlyAction(),
		proto.ActionArchiveUnwrapAndRewrap: wrap(handlers.HandleArchiveUnwrapAndRewrap).appOnlyAction(),

		// same-device org archive key rotation (staging-slot pattern)
		proto.ActionArchiveKeyRotateBegin:  wrap(handlers.HandleArchiveKeyRotateBegin).appOnlyAction(),
		proto.ActionArchiveKeyRotateCommit: wrap(handlers.HandleArchiveKeyRotateCommit).appOnlyAction(),
		proto.ActionArchiveKeyRotateAbort:  wrap(handlers.HandleArchiveKeyRotateAbort).appOnlyAction(),

		// per-account Archive / Recovery receiving keypair actions
		proto.ActionAccountArchiveKeyGenerate: wrap(handlers.HandleAccountArchiveKeyGenerate).appOnlyAction(),
	}
}
