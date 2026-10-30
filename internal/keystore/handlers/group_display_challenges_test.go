package handlers

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupDisplayChallengeConsumedOnceAndPurgedWithHandle(t *testing.T) {
	store := NewGroupDisplayChallengeStore()
	now := time.Unix(1000, 0)
	first := groupDisplayContext{groupHandle: "first-handle"}
	first.operationDigest[0] = 1
	if err := store.Put("first-challenge", first, now); err != nil {
		t.Fatalf("put first challenge: %v", err)
	}
	if got, ok := store.Consume("first-challenge", now); !ok || got != first {
		t.Fatal("first challenge was not consumed")
	}
	if _, ok := store.Consume("first-challenge", now); ok {
		t.Fatal("consumed challenge was reused")
	}
	if err := store.Put("second-challenge", first, now); err != nil {
		t.Fatalf("put second challenge: %v", err)
	}
	store.PurgeHandle("first-handle")
	if _, ok := store.Consume("second-challenge", now); ok {
		t.Fatal("closed handle retained a display challenge")
	}
}

func TestGroupDisplayChallengeExpiresAndBoundsPendingState(t *testing.T) {
	store := NewGroupDisplayChallengeStore()
	now := time.Unix(1000, 0)
	first := groupDisplayContext{groupHandle: "original"}
	if err := store.Put("challenge-0", first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("challenge-0", groupDisplayContext{groupHandle: "replacement"}, now); err == nil {
		t.Fatal("duplicate challenge replaced its original context")
	}
	if got, ok := store.Peek("challenge-0", now); !ok || got != first {
		t.Fatal("duplicate challenge changed the stored context")
	}
	for i := 1; i < groupDisplayMaxChallenges; i++ {
		if err := store.Put(fmt.Sprintf("challenge-%d", i), groupDisplayContext{}, now); err != nil {
			t.Fatalf("put challenge %d: %v", i, err)
		}
	}
	if err := store.Put("overflow", groupDisplayContext{}, now); err == nil {
		t.Fatal("pending challenge limit was ignored")
	}
	atDeadline := now.Add(groupDisplayChallengeTTL)
	if _, ok := store.Consume("challenge-0", atDeadline); ok {
		t.Fatal("expired challenge was consumed at its deadline")
	}
	if err := store.Put("fresh", groupDisplayContext{}, atDeadline); err != nil {
		t.Fatalf("expired pending state did not free capacity: %v", err)
	}
}

func TestGroupDisplayChallengeConcurrentConsumeHasOneWinner(t *testing.T) {
	store := NewGroupDisplayChallengeStore()
	now := time.Unix(1000, 0)
	if err := store.Put("one-use", groupDisplayContext{}, now); err != nil {
		t.Fatal(err)
	}
	const actors = 8
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	var winners atomic.Int32
	ready.Add(actors)
	done.Add(actors)
	for i := 0; i < actors; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			if _, ok := store.Consume("one-use", now); ok {
				winners.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("successful concurrent consumes = %d, want 1", got)
	}
}
