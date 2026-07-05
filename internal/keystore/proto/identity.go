// identity_models.go — RSA keypair / public key / alias signing payloads.
// GenerateKeypair / SignAlias / SignAliasWithTimestamp / SignChallengeToken
// request·response + GetPublicKey / GetServerPublicKey response.

package proto

type GenerateKeypairRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r GenerateKeypairRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	return requireString(r.Signature, "signature")
}

// SignAliasRequest
//
// If WrapKeyB64 is non-empty, the Keeper internally wraps the newly
// generated pending private key with wrap_key (AES-GCM 32B raw) and
// returns the wrapped result in the response's WrappedKeeper. Used in
// the signup flow to set up the Recovery Key.
//
// If WrapKeyB64 is empty, the original behavior (return signature +
// publickey only) is kept.
type SignAliasRequest struct {
	Alias      string `json:"alias"`
	WrapKeyB64 string `json:"wrap_key_b64,omitempty"`
}

func (r SignAliasRequest) Validate() error {
	return requireString(r.Alias, "alias")
}

type SignAliasWithTimestampRequest struct {
	Alias string `json:"alias"`
}

func (r SignAliasWithTimestampRequest) Validate() error {
	return requireString(r.Alias, "alias")
}

type SignChallengeTokenRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r SignChallengeTokenRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	return requireString(r.Signature, "signature")
}

type GenerateKeypairResponseData struct {
	PublicKey string `json:"publickey"`
}

type GetPublicKeyResponseData struct {
	PublicKey string `json:"publickey"`
}

type GetServerPublicKeyResponseData struct {
	PublicKey string `json:"publickey"`
}

type SignAliasResponseData struct {
	Signature     string `json:"signature"`
	PublicKey     string `json:"publickey"`
	WrappedKeeper string `json:"wrapped_keeper,omitempty"` // pending private key wrapped with wrap_key (set when WrapKeyB64 is provided in signup)
}

type SignAliasWithTimestampResponseData struct {
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

type SignChallengeTokenResponseData struct {
	Signature string `json:"signature"`
}

// ResetDeviceIdentityRequest carries no payload — see ActionResetDeviceIdentity.
type ResetDeviceIdentityRequest struct{}

// ResetDeviceIdentityResponseData reports the Keychain slots that were actually
// removed. Idempotent: absent slots are omitted, so the list is empty (never
// null — the handler emits `[]`) when nothing was present. Only slot names are
// returned; no key material is ever echoed.
type ResetDeviceIdentityResponseData struct {
	Cleared []string `json:"cleared"`
}
