package main

import (
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const startupSweepOrg = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

// prepareProcessApp is the only step between building the process App and
// handing it to the App RPC service and the message loop, so an expired
// session key is gone before any action is served (lv100 F1).
func TestPrepareProcessAppSweepsBeforeServing(t *testing.T) {
	store := testdouble.NewMemorySecretStore()
	now := time.Unix(1788999000, 0)
	app := keystore.NewApp(keystore.Deps{Store: store, Clock: func() time.Time { return now }})
	if begun := handlers.HandleArchiveSessionBegin(app.HandlersDeps(), proto.ArchiveSessionBeginRequest{OrgID: startupSweepOrg}); !begun.Success {
		t.Fatal("begin failed")
	}
	now = now.Add(time.Hour)

	served := prepareProcessApp(app)
	if value, _ := store.Get(config.Service, config.OrgArchiveSessionPrivateKeyPrefix+startupSweepOrg); value != "" {
		t.Fatal("the process app was handed to serving with an expired session key")
	}
	if served != app {
		t.Fatal("prepareProcessApp returned another app")
	}
}
