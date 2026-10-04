// session_code_models.go — SessionCode save payloads.

package proto

type SaveSessionCodeRequest struct {
	EncryptedSessionCode string `json:"encrypted_session_code"`
	Signature            string `json:"signature"`
	ServerKeyVersion     uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r SaveSessionCodeRequest) Validate() error {
	if _, err := requireBase64(r.EncryptedSessionCode, "encrypted_session_code"); err != nil {
		return err
	}
	return requireString(r.Signature, "signature")
}

type SaveSessionCodeResponseData struct {
	SessionCode string `json:"session_code"`
	// Promoted names the keypair the session code opened with: "signup" or
	// "recovery" when this save made a staged key active, "active" when the
	// key was already active (a login, or a repeated save).
	Promoted string `json:"promoted"`
}
