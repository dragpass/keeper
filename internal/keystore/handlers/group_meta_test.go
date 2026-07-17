// group_meta_test.go — HandleGroupEncryptMeta / HandleGroupDecryptMeta guards.
//
// Core guarantees:
//   1. roundtrip: encrypt_meta output feeds straight into decrypt_meta and
//      recovers the original plaintext fields (homomorphic mirror).
//   2. the encrypt output meta_fields use the combined Base64(IV||ct) form the
//      Extension stores per meta field (decodable, ≥ 12B).
//   3. empty plaintext fields are skipped (no ciphertext emitted).
//   4. batch decrypt fails the whole batch on the first bad ciphertext.
//   5. bad handle → not_found; expired session → expired_session.
//   6. encrypt response / logger echo the plaintext sentinel 0 times.
//   7. decrypt response carries plaintext metadata (carve-out) but never the
//      raw Group DEK bytes.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestHandleGroupMeta_RoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, raw := openSessionForFreshKey(t, deps)

	fields := map[string]string{
		"label":           "my-draglink-label",
		"target_url":      "https://example.com/login",
		"target_hostname": "example.com",
		"blank":           "", // skipped — no ciphertext emitted
	}

	encResp := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: handle,
		Fields:      fields,
	})
	if !encResp.Success {
		t.Fatalf("encrypt meta: %s", encResp.Error)
	}
	encData, ok := encResp.Data.(proto.GroupEncryptMetaResponseData)
	if !ok {
		t.Fatalf("encrypt data type = %T, want GroupEncryptMetaResponseData", encResp.Data)
	}

	// Empty plaintext field is skipped.
	if _, present := encData.MetaFields["blank"]; present {
		t.Errorf("empty field should be skipped, got %q", encData.MetaFields["blank"])
	}
	// Each ciphertext is combined Base64(IV(12)||ct) — decodable and ≥ 12B.
	for name, ct := range encData.MetaFields {
		rawCT, err := base64.StdEncoding.DecodeString(ct)
		if err != nil {
			t.Errorf("%s: ciphertext not Base64: %v", name, err)
		}
		if len(rawCT) < 12 {
			t.Errorf("%s: ciphertext shorter than 12B IV", name)
		}
	}

	// Feed encrypt output straight back into decrypt — the homomorphic mirror.
	decResp := HandleGroupDecryptMeta(deps, proto.GroupDecryptMetaRequest{
		GroupHandle: handle,
		MetaFields:  encData.MetaFields,
	})
	if !decResp.Success {
		t.Fatalf("decrypt meta: %s", decResp.Error)
	}
	decData := decResp.Data.(proto.GroupDecryptMetaResponseData)

	for _, name := range []string{"label", "target_url", "target_hostname"} {
		if decData.Fields[name] != fields[name] {
			t.Errorf("%s: got %q, want %q", name, decData.Fields[name], fields[name])
		}
	}
	if _, present := decData.Fields["blank"]; present {
		t.Errorf("skipped field must not reappear after roundtrip")
	}

	// The raw Group DEK must never appear in either response envelope.
	rawB64 := base64.StdEncoding.EncodeToString(raw)
	for _, resp := range []proto.BaseResponse{encResp, decResp} {
		j, _ := json.Marshal(resp)
		if strings.Contains(string(j), rawB64) {
			t.Errorf("response leaked raw Group DEK: %s", j)
		}
	}
}

// TestHandleGroupDecryptMeta_BatchPartialFailure — a single bad ciphertext
// fails the whole batch (fail-fast), mirroring aes_unwrap_and_decrypt_meta.
func TestHandleGroupDecryptMeta_BatchPartialFailure(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, _ := openSessionForFreshKey(t, deps)

	good := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: handle,
		Fields:      map[string]string{"label": "ok"},
	})
	goodCT := good.Data.(proto.GroupEncryptMetaResponseData).MetaFields["label"]

	resp := HandleGroupDecryptMeta(deps, proto.GroupDecryptMetaRequest{
		GroupHandle: handle,
		MetaFields: map[string]string{
			"label": goodCT,
			"bad":   base64.StdEncoding.EncodeToString([]byte("short")), // < 12B → whole batch fails
		},
	})
	if resp.Success {
		t.Fatalf("expected whole batch to fail on a single bad ciphertext")
	}
}

// TestHandleGroupEncryptMeta_TamperedCiphertextFailsDecrypt — a ciphertext
// sealed under a different Group DEK does not open, so the batch fails.
func TestHandleGroupDecryptMeta_WrongKeyFails(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handleA, _ := openSessionForFreshKey(t, deps)
	handleB, _ := openSessionForFreshKey(t, deps)

	enc := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: handleA,
		Fields:      map[string]string{"label": "secret-label"},
	})
	ct := enc.Data.(proto.GroupEncryptMetaResponseData).MetaFields["label"]

	resp := HandleGroupDecryptMeta(deps, proto.GroupDecryptMetaRequest{
		GroupHandle: handleB, // different key
		MetaFields:  map[string]string{"label": ct},
	})
	if resp.Success {
		t.Fatalf("expected decrypt failure under a different Group DEK")
	}
}

func TestHandleGroupMeta_BadHandle(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	const badHandle = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	encResp := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: badHandle,
		Fields:      map[string]string{"label": "x"},
	})
	if encResp.Success || encResp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("encrypt meta bad handle: success=%v code=%q, want not_found", encResp.Success, encResp.ErrorCode)
	}

	decResp := HandleGroupDecryptMeta(deps, proto.GroupDecryptMetaRequest{
		GroupHandle: badHandle,
		MetaFields:  map[string]string{"label": base64.StdEncoding.EncodeToString(make([]byte, 28))},
	})
	if decResp.Success || decResp.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("decrypt meta bad handle: success=%v code=%q, want not_found", decResp.Success, decResp.ErrorCode)
	}
}

func TestHandleGroupMeta_ExpiredSession(t *testing.T) {
	// Each direction uses its own store: an expired Use purges the handle, so a
	// second call on the same store would see not_found rather than expired.
	encDeps, _, _ := newTestDeps(t)
	encHandle, _ := openSessionForFreshKey(t, encDeps)
	encDeps.GroupSessions.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })
	encResp := HandleGroupEncryptMeta(encDeps, proto.GroupEncryptMetaRequest{
		GroupHandle: encHandle,
		Fields:      map[string]string{"label": "x"},
	})
	if encResp.Success || encResp.ErrorCode != string(errs.ErrCodeExpiredSession) {
		t.Fatalf("encrypt meta expired: success=%v code=%q, want expired_session", encResp.Success, encResp.ErrorCode)
	}

	decDeps, _, _ := newTestDeps(t)
	decHandle, _ := openSessionForFreshKey(t, decDeps)
	decDeps.GroupSessions.SetClock(func() time.Time { return time.Now().Add(1 * time.Hour) })
	decResp := HandleGroupDecryptMeta(decDeps, proto.GroupDecryptMetaRequest{
		GroupHandle: decHandle,
		MetaFields:  map[string]string{"label": base64.StdEncoding.EncodeToString(make([]byte, 28))},
	})
	if decResp.Success || decResp.ErrorCode != string(errs.ErrCodeExpiredSession) {
		t.Fatalf("decrypt meta expired: success=%v code=%q, want expired_session", decResp.Success, decResp.ErrorCode)
	}
}

// TestHandleGroupEncryptMeta_NoSecretInResponseOrLogger — the encrypt response
// envelope and the logger echo the plaintext sentinel and raw Group DEK 0 times.
func TestHandleGroupEncryptMeta_NoSecretInResponseOrLogger(t *testing.T) {
	deps, log, _ := newTestDeps(t)
	handle, raw := openSessionForFreshKey(t, deps)

	const sentinel = "GROUP_ENCRYPT_META_PLAINTEXT_SENTINEL"
	resp := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: handle,
		Fields:      map[string]string{"label": sentinel},
	})
	if !resp.Success {
		t.Fatalf("encrypt meta: %s", resp.Error)
	}

	respJSON, _ := json.Marshal(resp)
	for _, banned := range []string{sentinel, "plaintext"} {
		if strings.Contains(string(respJSON), banned) {
			t.Fatalf("encrypt response leaked %q: %s", banned, respJSON)
		}
	}
	if log.Contains(sentinel) {
		t.Fatalf("logger leaked plaintext sentinel: %v", log.Messages())
	}
	if log.Contains(base64.StdEncoding.EncodeToString(raw)) {
		t.Fatalf("logger leaked raw Group DEK: %v", log.Messages())
	}
}

// TestHandleGroupDecryptMeta_NoRawDEKInResponse — the decrypt response carries
// plaintext metadata (carve-out) but never the raw Group DEK bytes.
func TestHandleGroupDecryptMeta_NoRawDEKInResponse(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	handle, raw := openSessionForFreshKey(t, deps)

	enc := HandleGroupEncryptMeta(deps, proto.GroupEncryptMetaRequest{
		GroupHandle: handle,
		Fields:      map[string]string{"label": "visible-label"},
	})
	resp := HandleGroupDecryptMeta(deps, proto.GroupDecryptMetaRequest{
		GroupHandle: handle,
		MetaFields:  enc.Data.(proto.GroupEncryptMetaResponseData).MetaFields,
	})
	if !resp.Success {
		t.Fatalf("decrypt meta: %s", resp.Error)
	}
	data := resp.Data.(proto.GroupDecryptMetaResponseData)
	if data.Fields["label"] != "visible-label" {
		t.Errorf("carve-out plaintext metadata missing: %q", data.Fields["label"])
	}

	rawJSON, _ := json.Marshal(resp.Data)
	if strings.Contains(string(rawJSON), base64.StdEncoding.EncodeToString(raw)) {
		t.Error("decrypt response leaked raw Group DEK bytes")
	}
}
