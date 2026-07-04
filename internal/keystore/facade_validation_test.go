// facade_validation_test.go: HandleRequest payload Validate() branch
// checks. 17 sub-cases for signalias / signaliaswithtimestamp /
// signchallengetoken / generatekeypair / savesessioncode /
// recoverysign / recovery_session_open / recovery_session_close /
// generatekeypairwithrecoverywrap actions in a single table — covers
// empty / invalid fields.
package keystore

import "testing"

func TestHandleRequest_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"signalias empty alias", `{"action":"signalias","payload":{"alias":""}}`},
		{"signaliaswithtimestamp empty", `{"action":"signaliaswithtimestamp","payload":{"alias":""}}`},
		{"signchallengetoken empty token", `{"action":"signchallengetoken","payload":{"challenge_token":"","signature":""}}`},
		{"generatekeypair empty token", `{"action":"generatekeypair","payload":{"challenge_token":"","signature":""}}`},
		{"savesessioncode empty", `{"action":"savesessioncode","payload":{"encrypted_session_code":"","signature":""}}`},
		// recoverysign takes recovery_handle instead of old_private_key_pem.
		{"recoverysign empty token", `{"action":"recoverysign","payload":{"challenge_token":"","signature":"x","recovery_handle":"y"}}`},
		{"recoverysign empty signature", `{"action":"recoverysign","payload":{"challenge_token":"x","signature":"","recovery_handle":"y"}}`},
		{"recoverysign empty handle", `{"action":"recoverysign","payload":{"challenge_token":"x","signature":"y","recovery_handle":""}}`},
		// recovery_session_open payload validation
		{"recovery_session_open empty token", `{"action":"recovery_session_open","payload":{"challenge_token":"","signature":"s","wrapped_keeper_b64":"w","wrap_key_b64":"k"}}`},
		{"recovery_session_open empty signature", `{"action":"recovery_session_open","payload":{"challenge_token":"c","signature":"","wrapped_keeper_b64":"w","wrap_key_b64":"k"}}`},
		{"recovery_session_open empty wrapped", `{"action":"recovery_session_open","payload":{"challenge_token":"c","signature":"s","wrapped_keeper_b64":"","wrap_key_b64":"k"}}`},
		{"recovery_session_open empty wrap key", `{"action":"recovery_session_open","payload":{"challenge_token":"c","signature":"s","wrapped_keeper_b64":"w","wrap_key_b64":""}}`},
		{"recovery_session_close empty handle", `{"action":"recovery_session_close","payload":{"recovery_handle":""}}`},
		{"generatekeypairwithrecoverywrap empty token", `{"action":"generatekeypairwithrecoverywrap","payload":{"challenge_token":"","signature":"x","wrap_key_b64":"AA"}}`},
		{"generatekeypairwithrecoverywrap empty wrap_key", `{"action":"generatekeypairwithrecoverywrap","payload":{"challenge_token":"x","signature":"y","wrap_key_b64":""}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newFacadeTestApp()
			resp := app.HandleRequest([]byte(tt.msg))
			if resp.Success {
				t.Error("expected validation failure")
			}
		})
	}
}
