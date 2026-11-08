package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// splitStoreProbe counts every keychain access so a refused split can prove it
// never read the archive key, wrote a preparation journal, or deleted a slot.
type splitStoreProbe struct {
	keychain.SecretStore
	gets, sets, deletes int
}

func (p *splitStoreProbe) Get(service, account string) (string, error) {
	p.gets++
	return p.SecretStore.Get(service, account)
}

func (p *splitStoreProbe) Set(service, account, value string) error {
	p.sets++
	return p.SecretStore.Set(service, account, value)
}

func (p *splitStoreProbe) Delete(service, account string) error {
	p.deletes++
	return p.SecretStore.Delete(service, account)
}

// Until a server-signed split decision exists, a paired App process must not
// be able to collect archive-key shares under keys of its own choosing.
func TestArchiveKeySplit_RefusedWithoutSignedSplitDecision(t *testing.T) {
	for _, orgID := range []string{"", testOrgA} {
		t.Run("org="+orgID, func(t *testing.T) {
			deps, _, store := newTestDeps(t)
			seedActiveArchiveKey(t, deps)
			if orgID != "" {
				beginOrg(t, deps, orgID)
				if r := HandleArchiveKeyRotateCommit(deps, proto.ArchiveKeyRotateCommitRequest{OrgID: orgID}); !r.Success {
					t.Fatalf("commit org key: %s", r.Error)
				}
			}
			_, recipients := genAdminKeys(t, 3)
			probe := &splitStoreProbe{SecretStore: store}
			deps.Store = probe

			response := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{
				OperationID: "44444444-4444-4444-8444-444444444444",
				OrgID:       orgID, ThresholdN: 2, RecipientPublicKeys: recipients,
			})
			if response.Success || response.Data != nil {
				t.Fatal("archive key split returned shares without a signed split decision")
			}
			if response.ErrorCode != string(errs.ErrCodeArchiveSplitAuthorityRequired) {
				t.Fatalf("error code = %q", response.ErrorCode)
			}
			if probe.gets != 0 || probe.sets != 0 || probe.deletes != 0 {
				t.Fatalf("refused split touched the keychain: gets=%d sets=%d deletes=%d", probe.gets, probe.sets, probe.deletes)
			}
		})
	}
}
