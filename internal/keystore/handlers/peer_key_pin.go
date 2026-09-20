// peer_key_pin.go — the four pin management actions and the enforcement
// helper the two wrap actions share (account key trust v1).
//
// Nothing in this file returns key material. The pin actions deal in
// fingerprints, state words, and timestamps; enforcePeerKeyPins deals in a
// verdict. The one place a public key enters is peer_key_pin_verify, which
// needs the PEM precisely so it can refuse to take the caller's word for what
// that PEM hashes to.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.2, §6.4.

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// peerKeyPinStateExempt is what a recipient with no account id reports. The
// org archive key is the case that matters: it is an org resource rather than
// an account, so there is no peer to pin it against. An accepted gap, recorded
// here and in the threat model rather than papered over.
const peerKeyPinStateExempt = "exempt"

// peerKeyPinCheck is one recipient's input to the state machine. An empty
// accountID means "no pin to enforce" and short-circuits to exempt.
type peerKeyPinCheck struct {
	accountID  string
	observed   string
	statements []proto.KeyRotationStatement
}

// enforcePeerKeyPins runs the state machine for every recipient and, only if
// all of them pass, writes the resulting pins.
//
// The two passes are the contract, not an optimisation. A rotation wraps the
// Group DEK to every member at once; if the eleventh member's key had been
// swapped and the first ten were already wrapped, the org would split into
// people who can read the new DEK and people who cannot. So every recipient is
// judged before anything is produced, and one `changed` refuses the call whole.
func enforcePeerKeyPins(
	d Deps, ownerAccountID string, checks []peerKeyPinCheck,
) ([]string, proto.BaseResponse, bool) {
	states := make([]string, len(checks))
	type pendingPin struct {
		accountID string
		pin       keychain.PeerKeyPin
	}
	updates := make([]pendingPin, 0, len(checks))
	now := d.Now().Unix()

	for i, check := range checks {
		if check.accountID == "" {
			states[i] = peerKeyPinStateExempt
			continue
		}
		existing, err := loadPeerKeyPin(d.Store, ownerAccountID, check.accountID)
		if err != nil {
			d.Logger.Printf("peer key pin error: failed to read pin: %v", err)
			return nil, errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read peer key pin: "+err.Error()), false
		}
		outcome := evaluatePeerKeyTrust(existing, check.accountID, check.observed, check.statements, now)
		if !outcome.Allowed {
			d.Logger.Printf("peer key pin refused the wrap: %s", outcome.Reason)
			return nil, errs.CodeResponse(errs.ErrCodePeerKeyChanged, outcome.Reason), false
		}
		states[i] = string(outcome.State)
		updates = append(updates, pendingPin{accountID: check.accountID, pin: outcome.Pin})
	}

	// Persist before wrapping: a keyring that refuses the write should stop
	// the call, not leave a wrap behind with no record that it happened.
	for _, update := range updates {
		if err := keychain.SavePeerKeyPin(d.Store, ownerAccountID, update.accountID, update.pin); err != nil {
			d.Logger.Printf("peer key pin error: failed to save pin: %v", err)
			return nil, errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save peer key pin: "+err.Error()), false
		}
	}
	return states, proto.BaseResponse{Success: true}, true
}

// loadPeerKeyPin returns nil when the peer has no pin, so the state machine
// can tell "first observation" from "storage is broken".
func loadPeerKeyPin(store keychain.SecretStore, ownerAccountID, peerAccountID string) (*keychain.PeerKeyPin, error) {
	pin, err := keychain.GetPeerKeyPin(store, ownerAccountID, peerAccountID)
	if err != nil {
		if errors.Is(err, keychain.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pin, nil
}

// pinInfo projects a stored record onto the wire shape. last_rotation_fingerprint
// stays behind.
func pinInfo(accountID string, pin keychain.PeerKeyPin) proto.PeerKeyPinInfo {
	return proto.PeerKeyPinInfo{
		AccountID:   accountID,
		Fingerprint: pin.Fingerprint,
		State:       string(pin.State),
		FirstSeenAt: pin.FirstSeenAt,
		LastSeenAt:  pin.LastSeenAt,
		VerifiedAt:  pin.VerifiedAt,
	}
}

// HandlePeerKeyPinList returns every pin this owner holds on this device.
func HandlePeerKeyPinList(d Deps, req proto.PeerKeyPinListRequest) proto.BaseResponse {
	d.Logger.Println("peer key pin list request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	entries, err := keychain.ListPeerKeyPins(d.Store, req.OwnerAccountID)
	if err != nil {
		d.Logger.Printf("peer key pin list error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to list peer key pins: "+err.Error())
	}

	pins := make([]proto.PeerKeyPinInfo, 0, len(entries))
	for _, entry := range entries {
		pins = append(pins, pinInfo(entry.AccountID, entry.Pin))
	}

	// Count only. A pin list is a social graph, so the set itself does not go
	// into the log even though a single fingerprint would be harmless.
	d.Logger.Printf("peer key pin list successful (%d pins)", len(pins))
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPinListResponseData{Pins: pins}}
}

// HandlePeerKeyPinGet returns one pin, or reports that there is none.
func HandlePeerKeyPinGet(d Deps, req proto.PeerKeyPinGetRequest) proto.BaseResponse {
	d.Logger.Println("peer key pin get request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	pin, err := loadPeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID)
	if err != nil {
		d.Logger.Printf("peer key pin get error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read peer key pin: "+err.Error())
	}
	if pin == nil {
		d.Logger.Println("peer key pin get successful (no pin)")
		return proto.BaseResponse{Success: true, Data: proto.PeerKeyPinGetResponseData{Found: false}}
	}

	info := pinInfo(req.AccountID, *pin)
	d.Logger.Println("peer key pin get successful")
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPinGetResponseData{Found: true, Pin: &info}}
}

// HandlePeerKeyPinVerify settles a fingerprint a human compared out of band.
//
// The request carries both the fingerprint the user confirmed and the key the
// server is serving right now, and they have to agree. If they do not, the
// user checked one key while the server is handing out another — exactly the
// substitution the pin exists to catch — so the action fails and the pin is
// left alone rather than promoting the key nobody looked at.
func HandlePeerKeyPinVerify(d Deps, req proto.PeerKeyPinVerifyRequest) proto.BaseResponse {
	d.Logger.Println("peer key pin verify request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Parse before hashing: a string that starts with a PEM header but holds
	// no key should fail as a bad key, not settle as a trusted fingerprint.
	if _, err := crypto.ParsePublicKey(req.PublicKey); err != nil {
		d.Logger.Printf("peer key pin verify error: failed to parse public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse public key: "+err.Error())
	}
	if crypto.AccountKeyFingerprint([]byte(req.PublicKey)) != req.Fingerprint {
		d.Logger.Println("peer key pin verify error: fingerprint does not match the supplied public key")
		return errs.CodeResponse(
			errs.ErrCodeCryptoFailure,
			"fingerprint does not match the supplied public key; the pin was not changed",
		)
	}

	existing, err := loadPeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID)
	if err != nil {
		d.Logger.Printf("peer key pin verify error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read peer key pin: "+err.Error())
	}

	now := d.Now().Unix()
	// A peer with no pin can still be verified: the user checked the
	// fingerprint before anything was ever wrapped to it.
	pin := keychain.PeerKeyPin{V: keychain.PeerKeyPinVersion, FirstSeenAt: now}
	if existing != nil {
		pin = *existing
	}
	pin.Fingerprint = req.Fingerprint
	pin.State = keychain.PeerKeyPinStateVerified
	pin.VerifiedAt = now
	pin.LastSeenAt = now
	pin.LastRotationFingerprint = ""

	if err := keychain.SavePeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID, pin); err != nil {
		d.Logger.Printf("peer key pin verify error: failed to save pin: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save peer key pin: "+err.Error())
	}

	d.Logger.Println("peer key pin verify successful (pin is now verified)")
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPinVerifyResponseData{
		State:       string(keychain.PeerKeyPinStateVerified),
		Fingerprint: req.Fingerprint,
	}}
}

// HandlePeerKeyPinForget discards a pin. Idempotent.
func HandlePeerKeyPinForget(d Deps, req proto.PeerKeyPinForgetRequest) proto.BaseResponse {
	d.Logger.Println("peer key pin forget request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	forgotten, err := keychain.DeletePeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID)
	if err != nil {
		d.Logger.Printf("peer key pin forget error: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to forget peer key pin: "+err.Error())
	}

	d.Logger.Printf("peer key pin forget successful (forgotten=%t)", forgotten)
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyPinForgetResponseData{Forgotten: forgotten}}
}
