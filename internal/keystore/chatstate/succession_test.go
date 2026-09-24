package chatstate

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

const (
	succAccount = "b2222222-2222-4222-8222-222222222222"
	succOther   = "a1111111-1111-4111-8111-111111111111"
	succOldDev  = "d1111111-1111-4111-8111-111111111111"
	succNewDev  = "d2222222-2222-4222-8222-222222222222"
)

func leafKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// signed is old approving new, both keys given.
func signed(oldPub ed25519.PublicKey, oldPriv ed25519.PrivateKey, newPub ed25519.PublicKey) LeafHandover {
	h := LeafHandover{
		AccountID: succAccount, OldDeviceID: succOldDev, OldFingerprint: leafKeyFingerprint(oldPub),
		NewDeviceID: succNewDev, NewFingerprint: leafKeyFingerprint(newPub),
		IssuedAt: 1758240000, ExpiresAt: 1758240600,
	}
	h.Signature = ed25519.Sign(oldPriv, []byte(LeafHandoverCanonical(h)))
	return h
}

func TestLeafHandoverCanonical_IsTheContractBytes(t *testing.T) {
	h := LeafHandover{
		AccountID: succAccount, OldDeviceID: succOldDev, OldFingerprint: strings.Repeat("a", 64),
		NewDeviceID: succNewDev, NewFingerprint: strings.Repeat("b", 64), IssuedAt: 1758240000, ExpiresAt: 1758240600,
	}
	want := "dragpass.mls.leaf.handover|1|" + succAccount + "|" + succOldDev + "|" + strings.Repeat("a", 64) +
		"|" + succNewDev + "|" + strings.Repeat("b", 64) + "|1758240000|1758240600"
	if got := LeafHandoverCanonical(h); got != want {
		t.Fatalf("canonical = %q\nwant       %q", got, want)
	}
}

func TestLeafHandover_ValidateHoldsTheWindowAndTheShape(t *testing.T) {
	oldPub, oldPriv := leafKey(t)
	newPub, _ := leafKey(t)
	good := signed(oldPub, oldPriv, newPub)
	if err := good.VerifyUnder(oldPub); err != nil {
		t.Fatalf("a good handover = %v", err)
	}
	for name, mutate := range map[string]func(*LeafHandover){
		"window longer than ten minutes": func(h *LeafHandover) { h.ExpiresAt = h.IssuedAt + HandoverMaxSeconds + 1 },
		"expires before issued":          func(h *LeafHandover) { h.ExpiresAt = h.IssuedAt - 1 },
		"same device":                    func(h *LeafHandover) { h.NewDeviceID = h.OldDeviceID },
		"same key":                       func(h *LeafHandover) { h.NewFingerprint = h.OldFingerprint },
		"upper-case fingerprint":         func(h *LeafHandover) { h.NewFingerprint = strings.ToUpper(h.NewFingerprint) },
		"short signature":                func(h *LeafHandover) { h.Signature = h.Signature[:10] },
		"nil account":                    func(h *LeafHandover) { h.AccountID = "00000000-0000-0000-0000-000000000000" },
	} {
		h := good
		mutate(&h)
		if err := h.VerifyUnder(oldPub); !errors.Is(err, ErrHandoverInvalid) {
			t.Errorf("%s: %v; want ErrHandoverInvalid", name, err)
		}
	}
	// Any change to a signed field breaks the signature.
	moved := good
	moved.IssuedAt++
	if err := moved.VerifyUnder(oldPub); !errors.Is(err, ErrHandoverInvalid) {
		t.Errorf("a re-dated handover verified: %v", err)
	}
	other, _ := leafKey(t)
	if err := good.VerifyUnder(other); !errors.Is(err, ErrHandoverInvalid) {
		t.Errorf("a handover verified under another key: %v", err)
	}
}

func TestHandovers_RoundTripAndRefuseAnythingElse(t *testing.T) {
	oldPub, oldPriv := leafKey(t)
	newPub, _ := leafKey(t)
	h := signed(oldPub, oldPriv, newPub)
	ad, err := EncodeHandovers([]LeafHandover{h})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeHandovers(ad)
	if err != nil || len(back) != 1 || LeafHandoverCanonical(back[0]) != LeafHandoverCanonical(h) ||
		string(back[0].Signature) != string(h.Signature) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	if none, err := EncodeHandovers(nil); none != nil || err != nil {
		t.Fatalf("no handovers encode as %q, %v; want nothing", none, err)
	}
	if none, err := DecodeHandovers(nil); none != nil || err != nil {
		t.Fatalf("no data decodes as %v, %v", none, err)
	}
	for name, data := range map[string]string{
		"unknown field":     strings.Replace(string(ad), `"v":1`, `"v":1,"x":0`, 1),
		"trailing value":    string(ad) + `{}`,
		"other version":     strings.Replace(string(ad), `"v":1`, `"v":2`, 1),
		"empty list":        `{"v":1,"handovers":[]}`,
		"not json":          "handover",
		"bad signature b64": strings.Replace(string(ad), `"signature":"`, `"signature":"!`, 1),
		"too large":         strings.Repeat(" ", maxHandoverBytes+1),
	} {
		if _, err := DecodeHandovers([]byte(data)); !errors.Is(err, ErrHandoverInvalid) {
			t.Errorf("%s: %v; want ErrHandoverInvalid", name, err)
		}
	}
}

func succLeaf(account, device string, key ed25519.PublicKey, accountKey string) SuccessionLeaf {
	return SuccessionLeaf{AccountID: account, DeviceID: device, SignatureKey: key, AccountKey: accountKey}
}

func TestJudgeSuccession_OnlyTheOldLeafsApprovalHandsOverTheSeat(t *testing.T) {
	oldPub, oldPriv := leafKey(t)
	newPub, newPriv := leafKey(t)
	old := succLeaf(succAccount, succOldDev, oldPub, "k1")
	next := succLeaf(succAccount, succNewDev, newPub, "k1")
	base := SuccessionChange{CommitterAccountID: succOther, Removed: []SuccessionLeaf{old}, Added: []SuccessionLeaf{next}}

	refused := func(name string, c SuccessionChange) {
		t.Helper()
		var u *UnauthorizedCommitError
		if err := JudgeSuccession(c); !errors.As(err, &u) || u.CommitterAccountID != c.CommitterAccountID {
			t.Errorf("%s: %v; want an unauthorized commit naming the committer", name, err)
		}
	}
	refused("no handover", base)
	with := base
	with.Handovers = []LeafHandover{signed(oldPub, oldPriv, newPub)}
	if err := JudgeSuccession(with); err != nil {
		t.Fatalf("an approved succession = %v", err)
	}
	selfSigned := base
	selfSigned.Handovers = []LeafHandover{signed(oldPub, newPriv, newPub)}
	refused("the new leaf approving itself", selfSigned)

	otherNew, _ := leafKey(t)
	elsewhere := base
	elsewhere.Handovers = []LeafHandover{signed(oldPub, oldPriv, otherNew)}
	refused("an approval of another new leaf", elsewhere)

	wrongDevice := with
	h := signed(oldPub, oldPriv, newPub)
	h.OldDeviceID = "d3333333-3333-4333-8333-333333333333"
	h.Signature = ed25519.Sign(oldPriv, []byte(LeafHandoverCanonical(h)))
	wrongDevice.Handovers = []LeafHandover{h}
	refused("an approval naming another old device", wrongDevice)

	// A re-seat under the same key and a plain Add are not successions.
	reseat := SuccessionChange{CommitterAccountID: succOther, Removed: []SuccessionLeaf{old},
		Added: []SuccessionLeaf{succLeaf(succAccount, succOldDev, oldPub, "k1")}}
	if err := JudgeSuccession(reseat); err != nil {
		t.Errorf("a re-seat = %v", err)
	}
	add := SuccessionChange{CommitterAccountID: succOther, Added: []SuccessionLeaf{next}}
	if err := JudgeSuccession(add); err != nil {
		t.Errorf("a plain add = %v", err)
	}
}
