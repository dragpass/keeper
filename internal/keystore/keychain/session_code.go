package keychain

// session_code.go — SessionCode CRUD against a SecretStore.
//
// The session-code helper bodies from storage.go moved here as exported free
// functions; the keystore root's thin `*App` wrapper passes `a.Store` as the
// first argument to delegate — zero change to external signatures.
//
// SessionCode is the first step of user authentication (alias + SessionCode →
// RSA challenge). Refreshed at the end of the Recovery flow.

import "github.com/dragpass/keeper/config"

// SaveSessionCode stores the user's SessionCode.
func SaveSessionCode(store SecretStore, sessionCode string) error {
	return store.Set(config.Service, config.SessionCode, sessionCode)
}

// GetSessionCode returns the user's SessionCode.
func GetSessionCode(store SecretStore) (string, error) {
	return store.Get(config.Service, config.SessionCode)
}

// DeleteSessionCode removes the user's SessionCode.
func DeleteSessionCode(store SecretStore) error {
	return store.Delete(config.Service, config.SessionCode)
}
