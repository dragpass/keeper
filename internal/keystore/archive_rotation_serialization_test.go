package keystore

import (
	"sync"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// stageDeleteGate blocks archive_key_rotate_begin inside its first staging
// write until the test releases it.
type stageDeleteGate struct {
	SecretStore
	account string
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *stageDeleteGate) Delete(service, account string) error {
	if account == g.account {
		g.once.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	return g.SecretStore.Delete(service, account)
}

// The rotation regrant checks the staged archive key and wraps to it inside
// one handler call. A concurrent archive_key_rotate_begin for the same org
// must not land between those steps: every App request runs under requestMu,
// so the regrant cannot start while begin is replacing the stage.
func TestArchiveRotationRegrantWaitsForConcurrentRotateBegin(t *testing.T) {
	const org = "33333333-3333-4333-8333-333333333333"
	memory := testdouble.NewMemorySecretStore()
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(memory, archive.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePublicKey(memory, archive.PublicKey); err != nil {
		t.Fatal(err)
	}
	gate := &stageDeleteGate{
		SecretStore: memory, account: keychain.OrgArchiveStagingSlot(org).PrivateAccount,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	app := NewApp(Deps{Store: gate})

	begun := make(chan bool, 1)
	go func() {
		r := app.HandleAppRequest(sessionA, "", []byte(`{"action":"archive_key_rotate_begin","payload":{"org_id":"`+org+`"}}`))
		begun <- r.Success
	}()
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("rotate begin never reached its staging write")
	}

	regranted := make(chan struct{})
	go func() {
		app.HandleAppRequest(sessionA, "", []byte(`{"action":"archive_unwrap_and_rewrap","payload":{"org_id":"`+org+
			`","to_staged_archive_key":true,"owner_account_id":"11111111-1111-4111-8111-111111111111",`+
			`"wrapped_for_archive_b64":"AA==","recipient_public_key":"x"}}`))
		close(regranted)
	}()
	select {
	case <-regranted:
		t.Fatal("rotation regrant ran while rotate begin was replacing the stage")
	case <-time.After(300 * time.Millisecond):
	}

	close(gate.release)
	if ok := <-begun; !ok {
		t.Fatal("rotate begin failed")
	}
	select {
	case <-regranted:
	case <-time.After(10 * time.Second):
		t.Fatal("rotation regrant did not run after rotate begin finished")
	}
}
