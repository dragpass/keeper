package proto

// LoginAccountKeyBinding is the canonical ariadne signs, in App mode, to say
// which account key a login challenge was issued for. It must match
// pkg/api/v1/login.go in ariadne byte for byte. The domain line keeps it from
// equalling any other server-signed value.
func LoginAccountKeyBinding(challengeToken, fingerprint string) string {
	return "dragpass-login-account-key-v1\n" + challengeToken + "\n" + fingerprint
}

type AuthLoginPendingSignAliasRequest struct {
	Alias string `json:"alias"`
}

func (r AuthLoginPendingSignAliasRequest) Validate() error {
	return requireString(r.Alias, "alias")
}

// AuthLoginPendingCandidate is the login alias signature made with one staged
// account key, named by its fingerprint.
type AuthLoginPendingCandidate struct {
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Signature            string `json:"signature"`
}

type AuthLoginPendingSignAliasResponseData struct {
	Timestamp  int64                       `json:"timestamp"`
	Candidates []AuthLoginPendingCandidate `json:"candidates"`
}

type AuthLoginPendingSignChallengeRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"`
	// The server-signed statement of which account key the challenge is for.
	AccountKeyFingerprint      string `json:"account_key_fingerprint"`
	AccountKeySignature        string `json:"account_key_signature"`
	AccountKeyServerKeyVersion uint   `json:"account_key_server_key_version,omitempty"`
	// The password is checked against the server's password-wrapped DEK
	// before the challenge is signed, and nothing is stored.
	Password        string `json:"password"`
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
}

func (r AuthLoginPendingSignChallengeRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(r.AccountKeyFingerprint, "account_key_fingerprint"); err != nil {
		return err
	}
	if err := requireString(r.AccountKeySignature, "account_key_signature"); err != nil {
		return err
	}
	if err := requireString(r.Password, "password"); err != nil {
		return err
	}
	return requireString(r.EncryptedDEKB64, "encrypted_dek_b64")
}
