package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestArchiveSplitIntegrationPreservesOriginalBeforeConfirmation(t *testing.T) {
	d, _, store := newTestDeps(t)
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePublicKey(store, kp.PublicKey); err != nil {
		t.Fatal(err)
	}
	_, recipients := genAdminKeys(t, 2)
	response := HandleArchiveKeySplit(d, proto.ArchiveKeySplitRequest{OperationID: "44444444-4444-4444-8444-444444444444", ThresholdN: 2, RecipientPublicKeys: recipients})
	if !response.Success {
		t.Fatal("split preparation refused")
	}
	actual, err := keychain.GetArchivePrivateKey(store)
	if err != nil || actual != kp.PrivateKey {
		t.Fatal("original archive key lost before server confirmation and participant proofs")
	}
}

type splitJournalBarrierStore struct {
	keychain.SecretStore
	writes  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *splitJournalBarrierStore) Set(service, account, value string) error {
	if strings.HasPrefix(account, "archive_quorum_split_pending:") && s.writes.Add(1) == 1 {
		close(s.entered)
		<-s.release
	}
	return s.SecretStore.Set(service, account, value)
}

func TestArchiveSplitConcurrentRetryUsesOneDurableResult(t *testing.T) {
	d, _, store := newTestDeps(t)
	kp, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePrivateKey(store, kp.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SaveArchivePublicKey(store, kp.PublicKey); err != nil {
		t.Fatal(err)
	}
	_, recipients := genAdminKeys(t, 2)
	gate := &splitJournalBarrierStore{SecretStore: store, entered: make(chan struct{}), release: make(chan struct{})}
	d.Store = gate
	req := proto.ArchiveKeySplitRequest{OperationID: "77777777-7777-4777-8777-777777777777", ThresholdN: 2, RecipientPublicKeys: recipients}
	first := make(chan proto.BaseResponse, 1)
	second := make(chan proto.BaseResponse, 1)
	go func() { first <- HandleArchiveKeySplit(d, req) }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first preparation did not reach journal write")
	}
	go func() { second <- HandleArchiveKeySplit(d, req) }()
	var secondResult proto.BaseResponse
	completed := false
	select {
	case secondResult = <-second:
		completed = true
	case <-time.After(100 * time.Millisecond):
	}
	close(gate.release)
	var firstResult proto.BaseResponse
	select {
	case firstResult = <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first preparation did not finish")
	}
	if !completed {
		select {
		case secondResult = <-second:
		case <-time.After(5 * time.Second):
			t.Fatal("retry did not finish")
		}
	}
	if !firstResult.Success || !secondResult.Success || !reflect.DeepEqual(firstResult.Data, secondResult.Data) {
		t.Fatal("concurrent retry produced a different split result")
	}
	if gate.writes.Load() != 1 {
		t.Fatal("retry replaced the durable split journal")
	}
}
