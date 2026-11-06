package handlers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupRewrapChallengeStoreConsumesOnceAndDoesNotCrossInstances(t *testing.T) {
	now := time.Unix(100, 0)
	first := NewGroupRewrapChallengeStore()
	second := NewGroupRewrapChallengeStore()
	context := groupRewrapContext{accountID: "account", requestDigest: [32]byte{1}}
	if err := first.Put("challenge", context, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Consume("challenge", now); ok {
		t.Fatal("another Keeper instance accepted a local challenge")
	}
	if err := first.Put("challenge", context, now); err == nil {
		t.Fatal("duplicate challenge replaced the pending request")
	}
	if got, ok := first.Consume("challenge", now); !ok || got != context {
		t.Fatal("first consume failed")
	}
	if _, ok := first.Consume("challenge", now); ok {
		t.Fatal("challenge replay succeeded")
	}
	if err := first.Put("later", context, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Consume("later", now.Add(time.Minute)); ok {
		t.Fatal("expired challenge succeeded")
	}
}

func TestGroupRewrapChallengeStoreConcurrentConsumeHasOneWinner(t *testing.T) {
	now := time.Unix(100, 0)
	store := NewGroupRewrapChallengeStore()
	if err := store.Put("challenge", groupRewrapContext{requestDigest: [32]byte{1}}, now); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	var winners atomic.Int32
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if _, ok := store.Consume("challenge", now); ok {
				winners.Add(1)
			}
		}()
	}
	close(start)
	workers.Wait()
	if winners.Load() != 1 {
		t.Fatalf("challenge had %d consumers, want one", winners.Load())
	}
}
