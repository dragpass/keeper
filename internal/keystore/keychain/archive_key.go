package keychain

// archive_key.go — per-org Archive / Recovery keypair CRUD.
//
// A slot completely separate from the account identity keypair (RSA,
// keypair.go) and the request-signing key (request_key.go). Stores the org
// break-glass recovery keypair as PEM strings. The private key never leaves
// this slot — only public-key material and fingerprints cross into the
// Extension.

import (
	"errors"

	"github.com/dragpass/keeper/config"
)

// SaveArchivePrivateKey stores the RSA archive private key PEM.
func SaveArchivePrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.OrgArchivePrivateKey, privatePEM)
}

// GetArchivePrivateKey returns the stored archive private key PEM.
func GetArchivePrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchivePrivateKey)
}

// SaveArchivePublicKey stores the RSA archive public key PEM.
func SaveArchivePublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.OrgArchivePublicKey, publicPEM)
}

// GetArchivePublicKey returns the stored archive public key PEM.
func GetArchivePublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchivePublicKey)
}

// The rotation stage and the org-scoped slots are reached through
// ArchiveKeySlot below. archive_key_split wipes only the private half of the
// slot it split; the public half stays so the org still has an archive key.

// Per-account Archive / Recovery receiving keypair. Separate from the org
// archive keypair above: the account key receives handoff grants and quorum
// shares wrapped to the account directory public key, and must survive the
// org-slot wipe that archive_key_split performs.

// SaveAccountArchivePrivateKey stores the account archive private key PEM.
func SaveAccountArchivePrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.AccountArchivePrivateKey, privatePEM)
}

// GetAccountArchivePrivateKey returns the account archive private key PEM.
func GetAccountArchivePrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.AccountArchivePrivateKey)
}

// SaveAccountArchivePublicKey stores the account archive public key PEM.
func SaveAccountArchivePublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.AccountArchivePublicKey, publicPEM)
}

// GetAccountArchivePublicKey returns the account archive public key PEM.
func GetAccountArchivePublicKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.AccountArchivePublicKey)
}

// Archive quorum recovery-session ephemeral keypair.

// SaveArchiveSessionPrivateKey stores the recovery-session private key PEM.
func SaveArchiveSessionPrivateKey(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, config.OrgArchiveSessionPrivateKey, privatePEM)
}

// GetArchiveSessionPrivateKey returns the recovery-session private key PEM.
func GetArchiveSessionPrivateKey(store SecretStore) (string, error) {
	return store.Get(config.Service, config.OrgArchiveSessionPrivateKey)
}

// DeleteArchiveSessionPrivateKey removes the recovery-session private key PEM.
func DeleteArchiveSessionPrivateKey(store SecretStore) error {
	return store.Delete(config.Service, config.OrgArchiveSessionPrivateKey)
}

// SaveArchiveSessionPublicKey stores the recovery-session public key PEM.
func SaveArchiveSessionPublicKey(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, config.OrgArchiveSessionPublicKey, publicPEM)
}

// DeleteArchiveSessionPublicKey removes the recovery-session public key PEM.
func DeleteArchiveSessionPublicKey(store SecretStore) error {
	return store.Delete(config.Service, config.OrgArchiveSessionPublicKey)
}

// ArchiveKeySlot names the keyring accounts of one archive keypair: the
// active key or the rotation stage, of one org or of the whole device.
type ArchiveKeySlot struct {
	PrivateAccount string
	PublicAccount  string
	// Scope is "org" for an org-scoped slot and "device" for the device-wide
	// slot every Keeper before 0.0.58 used for all orgs.
	Scope string
}

const (
	ArchiveScopeOrg    = "org"
	ArchiveScopeDevice = "device"
)

var (
	deviceArchiveActiveSlot  = ArchiveKeySlot{config.OrgArchivePrivateKey, config.OrgArchivePublicKey, ArchiveScopeDevice}
	deviceArchiveStagingSlot = ArchiveKeySlot{config.OrgArchivePrivateKeyStaging, config.OrgArchivePublicKeyStaging, ArchiveScopeDevice}
)

// OrgArchiveActiveSlot is where a rotation of orgID commits to; the
// device-wide slot when orgID is empty.
func OrgArchiveActiveSlot(orgID string) ArchiveKeySlot {
	if orgID == "" {
		return deviceArchiveActiveSlot
	}
	return ArchiveKeySlot{config.OrgArchivePrivateKeyPrefix + orgID, config.OrgArchivePublicKeyPrefix + orgID, ArchiveScopeOrg}
}

// OrgArchiveStagingSlot is where a rotation of orgID stages its new key; the
// device-wide slot when orgID is empty.
func OrgArchiveStagingSlot(orgID string) ArchiveKeySlot {
	if orgID == "" {
		return deviceArchiveStagingSlot
	}
	return ArchiveKeySlot{config.OrgArchivePrivateKeyStagingPrefix + orgID, config.OrgArchivePublicKeyStagingPrefix + orgID, ArchiveScopeOrg}
}

// OrgArchiveActiveCandidates lists the slots that may hold orgID's active
// key, most specific first: the org slot, then the device-wide slot an org
// that never rotated on 0.0.58 still uses.
func OrgArchiveActiveCandidates(orgID string) []ArchiveKeySlot {
	if orgID == "" {
		return []ArchiveKeySlot{deviceArchiveActiveSlot}
	}
	return []ArchiveKeySlot{OrgArchiveActiveSlot(orgID), deviceArchiveActiveSlot}
}

// OrgArchiveStagingCandidates lists the slots that may hold orgID's stage.
// The device-wide stage is a fallback so a rotation an older Keeper began
// can still be committed or rewrapped to after the upgrade.
func OrgArchiveStagingCandidates(orgID string) []ArchiveKeySlot {
	if orgID == "" {
		return []ArchiveKeySlot{deviceArchiveStagingSlot}
	}
	return []ArchiveKeySlot{OrgArchiveStagingSlot(orgID), deviceArchiveStagingSlot}
}

// GetPrivate returns the private key PEM; ErrSecretNotFound when absent.
func (s ArchiveKeySlot) GetPrivate(store SecretStore) (string, error) {
	return store.Get(config.Service, s.PrivateAccount)
}

// GetPublic returns the public key PEM; ErrSecretNotFound when absent.
func (s ArchiveKeySlot) GetPublic(store SecretStore) (string, error) {
	return store.Get(config.Service, s.PublicAccount)
}

// SavePrivate stores the private key PEM.
func (s ArchiveKeySlot) SavePrivate(store SecretStore, privatePEM string) error {
	return store.Set(config.Service, s.PrivateAccount, privatePEM)
}

// SavePublic stores the public key PEM.
func (s ArchiveKeySlot) SavePublic(store SecretStore, publicPEM string) error {
	return store.Set(config.Service, s.PublicAccount, publicPEM)
}

// DeletePrivate removes the private key PEM.
func (s ArchiveKeySlot) DeletePrivate(store SecretStore) error {
	return store.Delete(config.Service, s.PrivateAccount)
}

// DeletePublic removes the public key PEM.
func (s ArchiveKeySlot) DeletePublic(store SecretStore) error {
	return store.Delete(config.Service, s.PublicAccount)
}

// FindArchiveKey returns the first candidate whose public half is present,
// with that public key. The public half decides which slot owns the org's
// key: a split leaves it in place after wiping the private half, and the
// search must not then fall through to another key. Only absence moves on to
// the next candidate; any other read error is returned, so a keyring failure
// never selects the device-wide key in place of the org's own.
func FindArchiveKey(store SecretStore, candidates []ArchiveKeySlot) (ArchiveKeySlot, string, bool, error) {
	for _, slot := range candidates {
		pub, err := slot.GetPublic(store)
		if errors.Is(err, ErrSecretNotFound) || (err == nil && pub == "") {
			continue
		}
		if err != nil {
			return ArchiveKeySlot{}, "", false, err
		}
		return slot, pub, true, nil
	}
	return ArchiveKeySlot{}, "", false, nil
}
