// peer_key_owner.go — the owner-reset payloads (account key trust v1, owner
// TOFU).
//
// No account id in either direction. The action clears whatever owner the
// device recorded; naming the one to clear would only let a caller confirm a
// guess, and there is nothing to confirm against — the next request records
// the new owner by using it.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.1.

package proto

// PeerKeyOwnerResetRequest takes nothing. Declared anyway so the action goes
// through the same decode / validate path as every other one.
type PeerKeyOwnerResetRequest struct{}

func (r PeerKeyOwnerResetRequest) Validate() error { return nil }

// PeerKeyOwnerResetResponseData reports whether an owner was actually
// recorded. Idempotent: resetting nothing succeeds with `reset:false`.
//
// The cleared account id is deliberately not echoed. The caller is the options
// page, which is about to ask the user to sign in as whoever they mean to be;
// handing the id back would only make the response worth intercepting.
type PeerKeyOwnerResetResponseData struct {
	Reset bool `json:"reset"`
}
