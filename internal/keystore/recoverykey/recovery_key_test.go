package recoverykey

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateFormatsSixGroups(t *testing.T) {
	key, err := Generate(bytes.NewReader(make([]byte, Length)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got, want := string(key), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

func TestNormalizeMatchesClientContract(t *testing.T) {
	key, err := Normalize([]byte(" abcd-efgh-jklm-npqr-stuv-wxyz "))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got, want := string(key), "ABCDEFGHJKLMNPQRSTUVWXYZ"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

func TestNormalizeRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"ABCD", "OBCDEFGHJKLMNPQRSTUVWXYZ"} {
		if _, err := Normalize([]byte(input)); err == nil {
			t.Fatalf("Normalize(%q) should fail", input)
		}
	}
}

func TestDeriveMatchesTypeScriptVectors(t *testing.T) {
	authSeed, wrapKey, err := Derive(
		[]byte("ABCDEFGHJKLMNPQRSTUVWXYZ"),
		"jinhyeok",
		Version,
	)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if want := "uTpqAHvvPRTOwPHmym3EiuIFnRYyn8sCAPuuQtybw64="; authSeed != want {
		t.Fatalf("auth seed = %q, want %q", authSeed, want)
	}
	if got := base64.StdEncoding.EncodeToString(wrapKey); got != "RF5xL8pd6o08IbDjb5/wKvxUD3PF2TDUxYenlz8zvbc=" {
		t.Fatalf("wrap key = %q", got)
	}
}
