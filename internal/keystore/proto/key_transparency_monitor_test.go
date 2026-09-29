package proto

import (
	"encoding/base64"
	"testing"
)

func TestKeyTransparencyMonitorRequestValidation(t *testing.T) {
	base := KeyTransparencyMonitorRequest{
		AccountID: "00000000-0000-4000-8000-000000000001",
		Events: []KeyTransparencyMonitorEventRequest{{
			EventID: "00000000-0000-4000-8000-000000000002", SourceType: "account_key_rotation",
			Evidence: KeyTransparencyEvidence{StatementB64: base64.StdEncoding.EncodeToString([]byte("statement"))},
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*KeyTransparencyMonitorRequest)
	}{
		{"empty", func(r *KeyTransparencyMonitorRequest) { r.Events = nil }},
		{"duplicate event id", func(r *KeyTransparencyMonitorRequest) { r.Events = append(r.Events, r.Events[0]) }},
		{"unsupported source", func(r *KeyTransparencyMonitorRequest) { r.Events[0].SourceType = "other" }},
		{"malformed statement base64", func(r *KeyTransparencyMonitorRequest) { r.Events[0].Evidence.StatementB64 = "%%%" }},
		{"oversized proof node", func(r *KeyTransparencyMonitorRequest) {
			r.Events[0].Evidence.InclusionProofB64 = []string{string(make([]byte, 129))}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := base
			request.Events = append([]KeyTransparencyMonitorEventRequest(nil), base.Events...)
			tc.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestKeyTransparencyMonitorAcceptsAccountEnrollment(t *testing.T) {
	request := KeyTransparencyMonitorRequest{
		AccountID: "00000000-0000-4000-8000-000000000001",
		Events: []KeyTransparencyMonitorEventRequest{{
			EventID: "00000000-0000-4000-8000-000000000002", SourceType: "account_key_enrollment",
			Evidence: KeyTransparencyEvidence{StatementB64: base64.StdEncoding.EncodeToString([]byte("statement"))},
		}},
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("account enrollment event rejected: %v", err)
	}
}
