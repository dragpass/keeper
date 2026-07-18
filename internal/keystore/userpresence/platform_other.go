//go:build !darwin

package userpresence

func NewPlatform() UserPresence {
	return Unavailable{}
}

func PrepareProcessMainThread() {}

// RunHost runs the Native Messaging loop directly on platforms without a
// trusted desktop UI backend.
func RunHost(host func()) {
	host()
}
