package keystore

import (
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const startupSweepOrg = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

// A Keeper restarted after a crash destroys an expired session key before it
// serves any action (lv100 F1).
func TestStartupDestroysAnExpiredArchiveSessionKey(t *testing.T) {
	store := testdouble.NewMemorySecretStore()
	if _, _, err := keychain.SetAccountBinding(store, startupSweepOrg, "test", true); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, "test account public key"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1788999000, 0)
	app := NewApp(Deps{Store: store, Clock: func() time.Time { return now }})
	if begun := handlers.HandleArchiveSessionBegin(app.HandlersDeps(), proto.ArchiveSessionBeginRequest{OrgID: startupSweepOrg}); !begun.Success {
		t.Fatal("begin failed")
	}

	app.SweepExpiredArchiveSession()
	if value, _ := store.Get(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+startupSweepOrg); value == "" {
		t.Fatal("startup sweep destroyed a live session key")
	}

	now = now.Add(time.Hour)
	app.SweepExpiredArchiveSession()
	if value, _ := store.Get(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+startupSweepOrg); value != "" {
		t.Fatal("startup sweep kept an expired session key")
	}
}
