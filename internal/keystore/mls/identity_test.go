package mls

import (
	"bytes"
	"testing"
)

func TestCredentialIdentity_RoundTripsAndRefusesOtherSpellings(t *testing.T) {
	const account, device = "11111111-1111-4111-8111-111111111111", "44444444-4444-4444-8444-444444444444"
	identity := CredentialIdentity(account, device)
	want := "dragpass.mls.credential|1|" + account + "|" + device
	if string(identity) != want {
		t.Fatalf("identity = %q, want %q", identity, want)
	}
	gotAccount, gotDevice, err := ParseCredentialIdentity(identity)
	if err != nil || gotAccount != account || gotDevice != device {
		t.Fatalf("parse = (%q, %q, %v)", gotAccount, gotDevice, err)
	}

	for _, bad := range [][]byte{
		nil,
		[]byte("alice@device-1"),
		[]byte("dragpass.mls.credential|2|" + account + "|" + device),
		[]byte("dragpass.mls.leaf|1|" + account + "|" + device),
		[]byte("dragpass.mls.credential|1|" + account),
		[]byte("dragpass.mls.credential|1|" + account + "|" + device + "|extra"),
		[]byte("dragpass.mls.credential|1||" + device),
		[]byte("dragpass.mls.credential|1|" + account + "|" + "44444444-4444-4444-8444-44444444444A"),
		append(bytes.Clone(identity), '\n'),
	} {
		if _, _, err := ParseCredentialIdentity(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
