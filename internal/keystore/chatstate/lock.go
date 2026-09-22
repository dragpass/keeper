// lock.go — the per-conversation lock.
//
// The mechanism is the one personal_key_bundle_lock*.go already proves on this
// codebase: an in-process gate in front of an advisory file lock (unix flock,
// windows LockFileEx). The policy is not, and the differences are the reason
// this is a separate implementation rather than a call into that one.
//
//   - One lock per conversation, not one global lock. Key rotation is rare
//     enough that a single queue costs nothing; putting every conversation in
//     one queue is a different proposition.
//   - A short ceiling. 5 seconds is fine for a rotation nobody is watching and
//     wrong for a send somebody is waiting on.
//   - No store-type bypass. withPersonalKeyBundleLock skips the file lock
//     entirely when the store is not the platform keyring, which would leave
//     the two-process tests here running a path with no lock in it and passing.
//     Nothing in this package looks at the store type.
//
// The ceiling below is a starting value, not a measured one. What it should be
// depends on the per-message keyring cost, which has not been measured on any
// of the three platforms.

package chatstate

import (
	"os"
	"sync"
	"time"
)

const (
	// LockTimeout bounds how long a conversation waits for another process.
	LockTimeout = 1500 * time.Millisecond

	lockPollInterval = 5 * time.Millisecond
)

// conversationGates serializes goroutines inside this process before they reach
// the file lock. flock is per open file description, so two goroutines here
// would otherwise each open the file and contend through the kernel, turning an
// in-process overlap into a timeout.
var conversationGates sync.Map // lock file path -> chan struct{}

func conversationGate(path string) chan struct{} {
	gate, _ := conversationGates.LoadOrStore(path, make(chan struct{}, 1))
	return gate.(chan struct{})
}

// acquireConversationLock takes the in-process gate and then the file lock,
// both under one deadline, and returns the release for the pair.
func acquireConversationLock(path string, timeout time.Duration) (func(), error) {
	gate := conversationGate(path)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case gate <- struct{}{}:
	case <-timer.C:
		return nil, ErrLockTimeout
	}

	release, err := acquireFileLock(path, timeout)
	if err != nil {
		<-gate
		return nil, err
	}
	return func() {
		release()
		<-gate
	}, nil
}

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func waitForFileLock(timeout time.Duration, tryLock func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryLock()
		if err != nil {
			return err
		}
		if acquired {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrLockTimeout
		}
		if remaining < lockPollInterval {
			time.Sleep(remaining)
		} else {
			time.Sleep(lockPollInterval)
		}
	}
}
