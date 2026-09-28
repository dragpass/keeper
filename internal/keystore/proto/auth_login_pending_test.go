package proto

import "testing"

// The binding is signed by ariadne (pkg/api/v1/login.go) and checked here;
// one differing byte and no pending sign-in ever verifies.
func TestLoginAccountKeyBindingMatchesAriadne(t *testing.T) {
	if got := LoginAccountKeyBinding("challenge", "ab12"); got != "dragpass-login-account-key-v1\nchallenge\nab12" {
		t.Fatalf("binding = %q", got)
	}
}

func TestAuthLoginPendingSignChallengeRequestValidation(t *testing.T) {
	valid := AuthLoginPendingSignChallengeRequest{
		ChallengeToken: "c", Signature: "s",
		AccountKeyFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AccountKeySignature:   "k", Password: "p", EncryptedDEKB64: "d",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	for name, edit := range map[string]func(*AuthLoginPendingSignChallengeRequest){
		"uppercase fingerprint": func(r *AuthLoginPendingSignChallengeRequest) {
			r.AccountKeyFingerprint = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
		},
		"no binding signature": func(r *AuthLoginPendingSignChallengeRequest) { r.AccountKeySignature = "" },
		"no password":          func(r *AuthLoginPendingSignChallengeRequest) { r.Password = "" },
		"no encrypted DEK":     func(r *AuthLoginPendingSignChallengeRequest) { r.EncryptedDEKB64 = "" },
	} {
		request := valid
		edit(&request)
		if request.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
