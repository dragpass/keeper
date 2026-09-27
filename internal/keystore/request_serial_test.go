package keystore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// overlapStore records whether two keychain calls ever ran at once.
type overlapStore struct {
	SecretStore
	inFlight atomic.Int32
	overlap  atomic.Bool
}

func (s *overlapStore) enter() func() {
	if s.inFlight.Add(1) > 1 {
		s.overlap.Store(true)
	}
	time.Sleep(time.Millisecond)
	return func() { s.inFlight.Add(-1) }
}

func (s *overlapStore) Get(service, account string) (string, error) {
	defer s.enter()()
	return s.SecretStore.Get(service, account)
}

func (s *overlapStore) Set(service, account, value string) error {
	defer s.enter()()
	return s.SecretStore.Set(service, account, value)
}

func (s *overlapStore) Delete(service, account string) error {
	defer s.enter()()
	return s.SecretStore.Delete(service, account)
}

// The local RPC owner serves the App, proxied hosts and its own stdio at the
// same time, while every handler was written for the one-at-a-time Native
// Messaging loop (a read-modify-write of the keychain, the e2e mock keyring's
// plain map). HandleRequest therefore runs one request at a time.
func TestHandleRequestRunsOneRequestAtATime(t *testing.T) {
	store := &overlapStore{SecretStore: NewMemorySecretStore()}
	app := NewApp(Deps{Store: store})
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			app.HandleRequest([]byte(`{"action":"request_key_status"}`))
		}()
	}
	wait.Wait()
	if store.overlap.Load() {
		t.Fatal("two requests touched the keychain at the same time")
	}
}
