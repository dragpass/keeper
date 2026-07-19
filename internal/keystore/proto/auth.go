package proto

type AuthSignupPrepareRequest struct {
	Alias    string `json:"alias"`
	Password string `json:"password,omitempty"`
}

func (r AuthSignupPrepareRequest) Validate() error {
	return requireString(r.Alias, "alias")
}

type AuthSignupPrepareResponseData struct {
	PasswordWrappedDEKB64 string `json:"password_wrapped_dek_b64"`
	DeviceWrappedDEKB64   string `json:"device_wrapped_dek_b64"`
	RecoveryAuthSeed      string `json:"recovery_auth_seed"`
	RecoveryWrappedKeeper string `json:"recovery_wrapped_keeper"`
	RecoveryKeyVersion    uint   `json:"recovery_key_version"`
	RecoveryKeyHandle     string `json:"recovery_key_handle"`
	RecoveryKeyExpiresAt  int64  `json:"recovery_key_expires_at_ms"`
	Signature             string `json:"signature"`
	PublicKey             string `json:"publickey"`
}

type AuthRecoveryKeyShowRequest struct {
	RecoveryKeyHandle string `json:"recovery_key_handle"`
}

func (r AuthRecoveryKeyShowRequest) Validate() error {
	return requireHandle(r.RecoveryKeyHandle, "recovery_key_handle")
}

type AuthRecoveryKeyShowResponseData struct{}

type AuthRecoveryReissuePrepareRequest struct {
	Alias             string `json:"alias"`
	RecoveryKeyHandle string `json:"recovery_key_handle,omitempty"`
}

func (r AuthRecoveryReissuePrepareRequest) Validate() error {
	if err := requireString(r.Alias, "alias"); err != nil {
		return err
	}
	if r.RecoveryKeyHandle == "" {
		return nil
	}
	return requireHandle(r.RecoveryKeyHandle, "recovery_key_handle")
}

type AuthRecoveryReissuePrepareResponseData struct {
	RecoveryAuthSeed      string `json:"recovery_auth_seed"`
	RecoveryWrappedKeeper string `json:"recovery_wrapped_keeper"`
	RecoveryKeyVersion    uint   `json:"recovery_key_version"`
	RecoveryKeyHandle     string `json:"recovery_key_handle"`
	RecoveryKeyExpiresAt  int64  `json:"recovery_key_expires_at_ms,omitempty"`
}

type AuthRecoveryBeginRequest struct {
	Alias       string `json:"alias"`
	RecoveryKey string `json:"recovery_key"`
}

func (r AuthRecoveryBeginRequest) Validate() error {
	if err := requireString(r.Alias, "alias"); err != nil {
		return err
	}
	return requireString(r.RecoveryKey, "recovery_key")
}

type AuthRecoveryBeginResponseData struct {
	RecoveryAuthSeed    string `json:"recovery_auth_seed"`
	EnteredKeyHandle    string `json:"entered_recovery_key_handle"`
	EnteredKeyExpiresAt int64  `json:"entered_recovery_key_expires_at_ms"`
}

type AuthRecoveryPrepareRequest struct {
	Alias              string `json:"alias"`
	EnteredKeyHandle   string `json:"entered_recovery_key_handle"`
	ChallengeToken     string `json:"challenge_token"`
	Signature          string `json:"signature"`
	WrappedKeeperB64   string `json:"wrapped_keeper_b64"`
	RecoveryKeyVersion int    `json:"recovery_key_version"`
	ServerKeyVersion   uint   `json:"server_key_version,omitempty"`
}

func (r AuthRecoveryPrepareRequest) Validate() error {
	if err := requireString(r.Alias, "alias"); err != nil {
		return err
	}
	if err := requireHandle(r.EnteredKeyHandle, "entered_recovery_key_handle"); err != nil {
		return err
	}
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	if _, err := requireBase64(r.WrappedKeeperB64, "wrapped_keeper_b64"); err != nil {
		return err
	}
	return requirePositiveVersion(r.RecoveryKeyVersion, "recovery_key_version")
}

type AuthRecoveryPrepareResponseData struct {
	OldChallengeSignature string `json:"old_challenge_signature"`
	RecoveryHandle        string `json:"recovery_handle"`
	RecoveryExpiresAt     int64  `json:"recovery_expires_at_ms"`
	NewPublicKey          string `json:"new_publickey"`
	NewRecoveryAuthSeed   string `json:"new_recovery_auth_seed"`
	NewWrappedKeeper      string `json:"new_recovery_wrapped_keeper"`
	NewRecoveryKeyVersion uint   `json:"new_recovery_key_version"`
	NewRecoveryKeyHandle  string `json:"new_recovery_key_handle"`
	NewRecoveryKeyExpires int64  `json:"new_recovery_key_expires_at_ms"`
}
