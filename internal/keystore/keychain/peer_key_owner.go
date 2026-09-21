package keychain

// peer_key_owner.go — the device's recorded pin owner (account key trust v1,
// owner TOFU).
//
// One entry under config.Service, no owner in the name, next to
// peer-key-policy:
//
//	peer-key-owner → {"v":1,"account_id":"<uuid>","recorded_at":1758240000}
//
// Why it exists. A pin lives at `peer-pin:<owner>:<peer>`, and the owner half
// reaches the Keeper as a request field whose original source is the server
// (`GET /account/me` → account id). The whole point of a pin is that a
// malicious server cannot get a Group DEK wrapped to a key it substituted —
// but a server that also reports a *different* account id moves every lookup
// into a namespace that has never been written to. Every peer then reads as a
// first observation, TOFU allows the wrap, and the pins a human verified sit
// untouched in the old namespace where nothing consults them. The same lie
// empties peer_key_pin_list, so the SPA's blocked banner has nothing to draw.
//
// So the Keeper records the first owner id it is ever given and refuses any
// request that carries a different one.
//
// What this buys and what it does not. It stops a server that *switches* the
// id after the fact — which is the attack above, because the pins that matter
// were written under the first id. It does not stop a server that lies
// consistently from the very first use: that server picks the namespace, and
// the Keeper has no independent source for an account id to check it against
// (the id is a server-side concept; nothing in the Keychain derives it). That
// residual case is harmless, though, because the namespace is only a label.
// Pins written under it still pin: the peer fingerprints recorded there are
// the real ones, and substituting a peer key later still lands on `changed`.
//
// Not owner-scoped, obviously — it is the thing that decides what "owner"
// means on this device.

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
)

// PeerKeyOwnerVersion is the schema version written into the record. A reader
// that meets a higher number is looking at a format it does not know.
const PeerKeyOwnerVersion = 1

// PeerKeyOwner is the stored record. RecordedAt is Unix seconds and is kept
// for diagnostics only; nothing branches on it.
type PeerKeyOwner struct {
	V          int    `json:"v"`
	AccountID  string `json:"account_id"`
	RecordedAt int64  `json:"recorded_at"`
}

// GetPeerKeyOwner reads the recorded owner. The bool reports whether one was
// there: absence is the ordinary first-run state, not a failure, and the
// caller turns it into "record this one".
func GetPeerKeyOwner(store SecretStore) (PeerKeyOwner, bool, error) {
	raw, err := store.Get(config.Service, config.PeerKeyOwnerAccount)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return PeerKeyOwner{}, false, nil
		}
		return PeerKeyOwner{}, false, err
	}
	var owner PeerKeyOwner
	if err := json.Unmarshal([]byte(raw), &owner); err != nil {
		// An error rather than a silent fall back to "no owner recorded".
		// Falling back would turn an unreadable record into a free pass for
		// whatever id the next request happens to carry, which is exactly the
		// move this slot exists to refuse.
		return PeerKeyOwner{}, false, errors.New("peer key owner record is not readable JSON")
	}
	if owner.AccountID == "" {
		return PeerKeyOwner{}, false, errors.New("peer key owner record names no account")
	}
	return owner, true, nil
}

// SavePeerKeyOwner writes the record, stamping the current schema version.
func SavePeerKeyOwner(store SecretStore, accountID string, recordedAt int64) error {
	encoded, err := json.Marshal(PeerKeyOwner{
		V:          PeerKeyOwnerVersion,
		AccountID:  accountID,
		RecordedAt: recordedAt,
	})
	if err != nil {
		return err
	}
	return store.Set(config.Service, config.PeerKeyOwnerAccount, string(encoded))
}

// DeletePeerKeyOwner clears the record. Idempotent: the bool reports whether
// one was actually there.
//
// Pins are deliberately left behind. A device that switches owners keeps the
// previous owner's trust records under their own prefix, so switching back
// finds them again — the same reasoning that keeps logout from dropping pins.
func DeletePeerKeyOwner(store SecretStore) (bool, error) {
	if err := store.Delete(config.Service, config.PeerKeyOwnerAccount); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
