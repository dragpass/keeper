// facade_request_id_test.go: verifies request_id echo multiplexing
// across five branches — success / unknown action / validation failure /
// omitted / invalid JSON — confirming request_id is echoed verbatim in
// the response (or comes out empty as appropriate).
package keystore

import "testing"

// TestHandleRequest_RequestID_EchoedOnSuccess verifies a request_id is
// echoed verbatim in a success response. The foundation for Extension-
// side concurrent-request multiplexing.
func TestHandleRequest_RequestID_EchoedOnSuccess(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"ping","request_id":"req-abc-123"}`
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("ping failed: %s", resp.Error)
	}
	if resp.RequestID != "req-abc-123" {
		t.Errorf("request_id echo mismatch: got %q, want %q", resp.RequestID, "req-abc-123")
	}
}

// TestHandleRequest_RequestID_EchoedOnUnknownAction verifies request_id
// is echoed even in error responses (the Extension needs to dispatch
// the error to the correct pending entry).
func TestHandleRequest_RequestID_EchoedOnUnknownAction(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"doesnotexist","request_id":"req-err-999"}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected failure for unknown action")
	}
	if resp.RequestID != "req-err-999" {
		t.Errorf("request_id echo on error mismatch: got %q, want %q", resp.RequestID, "req-err-999")
	}
}

// TestHandleRequest_RequestID_EchoedOnValidationError verifies that a
// payload Validate() failure response also echoes request_id (covers
// the internal-error path of process).
func TestHandleRequest_RequestID_EchoedOnValidationError(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"savedevicekey","request_id":"req-validate-777","payload":{"key":""}}`
	resp := app.HandleRequest([]byte(msg))
	if resp.Success {
		t.Error("expected validation failure for empty key")
	}
	if resp.RequestID != "req-validate-777" {
		t.Errorf("request_id echo on validation error mismatch: got %q, want %q", resp.RequestID, "req-validate-777")
	}
}

// TestHandleRequest_RequestID_OmittedKeepsEmpty verifies backwards
// compatibility: when an older Extension omits request_id, the response
// also goes out as an empty string.
func TestHandleRequest_RequestID_OmittedKeepsEmpty(t *testing.T) {
	app := newFacadeTestApp()
	msg := `{"action":"ping"}`
	resp := app.HandleRequest([]byte(msg))
	if !resp.Success {
		t.Fatalf("ping failed: %s", resp.Error)
	}
	if resp.RequestID != "" {
		t.Errorf("request_id should be empty when omitted, got %q", resp.RequestID)
	}
}

// TestHandleRequest_RequestID_InvalidJSONYieldsEmpty verifies that when
// JSON parsing fails the request_id can't be read, so an empty string
// goes out.
func TestHandleRequest_RequestID_InvalidJSONYieldsEmpty(t *testing.T) {
	app := newFacadeTestApp()
	resp := app.HandleRequest([]byte(`{not valid json`))
	if resp.Success {
		t.Error("expected failure for invalid JSON")
	}
	if resp.RequestID != "" {
		t.Errorf("request_id should be empty when JSON parsing fails, got %q", resp.RequestID)
	}
}
