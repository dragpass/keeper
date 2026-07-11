// archive_key.go — per-org Archive / Recovery keypair payloads.
//
//   - archive_key_generate : generate an RSA archive keypair if none exists.
//     Idempotent — when an active key is already present, return only its meta.
//   - archive_key_status   : whether an active archive key exists + public key.
//
// The archive keypair is an org break-glass recovery key. Its private key lives
// only in the org_archive_private_key keychain slot and is never used for
// identity / login / recovery / request signing.
//
// publickey is an RSA public-key PEM string. fingerprint is
// hex(sha256(publickey PEM)) — the same identifier the server and Extension
// derive for the archive grant's recipient_key_fingerprint.

package proto

type ArchiveKeyGenerateRequest struct{}

func (r ArchiveKeyGenerateRequest) Validate() error { return nil }

type ArchiveKeyGenerateResponseData struct {
	PublicKey   string `json:"publickey"`   // RSA public key PEM
	Fingerprint string `json:"fingerprint"` // hex(sha256(public key PEM))
}

type ArchiveKeyStatusRequest struct{}

func (r ArchiveKeyStatusRequest) Validate() error { return nil }

type ArchiveKeyStatusResponseData struct {
	HasActive   bool   `json:"has_active"`
	PublicKey   string `json:"publickey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
