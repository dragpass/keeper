package proto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validHandover() MLSLeafHandover {
	return MLSLeafHandover{
		AccountID:         "b2222222-2222-4222-8222-222222222222",
		OldDeviceID:       "d1111111-1111-4111-8111-111111111111",
		OldSignatureKeyFP: strings.Repeat("a", 64),
		NewDeviceID:       "d2222222-2222-4222-8222-222222222222",
		NewSignatureKeyFP: strings.Repeat("b", 64),
		IssuedAt:          1758240000,
		ExpiresAt:         1758240600,
		Signature:         base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
}

func TestMLSLeafHandover_Validate(t *testing.T) {
	if err := validHandover().Validate("h"); err != nil {
		t.Fatalf("valid handover = %v", err)
	}
	for name, mutate := range map[string]func(*MLSLeafHandover){
		"window over 600 s": func(h *MLSLeafHandover) { h.ExpiresAt = h.IssuedAt + 601 },
		"expires before":    func(h *MLSLeafHandover) { h.ExpiresAt = h.IssuedAt - 1 },
		"upper-case fp":     func(h *MLSLeafHandover) { h.NewSignatureKeyFP = strings.Repeat("B", 64) },
		"not a uuid":        func(h *MLSLeafHandover) { h.OldDeviceID = "d1" },
		"63-byte signature": func(h *MLSLeafHandover) { h.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63)) },
		"signature not b64": func(h *MLSLeafHandover) { h.Signature = "!!" },
		"issued_at zero":    func(h *MLSLeafHandover) { h.IssuedAt = 0 },
	} {
		h := validHandover()
		mutate(&h)
		if err := h.Validate("h"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMLSReplace_AHandoverMustBeForTheAccountBeingReplaced(t *testing.T) {
	h := validHandover()
	listed := []ChatStateLeafReplacement{{AccountID: h.AccountID, NewSignatureKeyFP: h.NewSignatureKeyFP}}
	kp := base64.StdEncoding.EncodeToString([]byte("kp"))
	if err := validateMLSReplace([]MLSReplaceMember{{AccountID: h.AccountID, KeyPackageB64: kp, Handover: &h}}, listed); err != nil {
		t.Fatalf("a matching handover = %v", err)
	}
	other := h
	other.AccountID = "a1111111-1111-4111-8111-111111111111"
	if err := validateMLSReplace([]MLSReplaceMember{{AccountID: h.AccountID, KeyPackageB64: kp, Handover: &other}}, listed); err == nil {
		t.Fatal("a handover for another account was accepted")
	}
}
