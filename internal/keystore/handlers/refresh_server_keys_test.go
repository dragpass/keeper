// refresh_server_keys_test.go — HandleRefreshServerKeys e2e verification.
//
// Coverage:
//  1. Validate — keys empty / 0 active / multiple actives / invalid status value
//  2. Root embedded: reject fingerprint mismatch
//  3. Root embedded: every key must have root_signature
//  4. Root embedded: reject bad signature
//  5. Root embedded: valid signature → updated_versions/active_version/root_verified=true
//  6. Root missing: a release build installs nothing; only a keeper_e2e
//     build skips signature verification (TOFU pin)
//  7. Verify the 4 Keychain slots are updated (versioned, active pointer,
//     legacy mirror, fingerprint pin)
//
// Migrated from the keystore root's refresh_server_keys_facade_test.go. All
// keychain helpers were updated to use deps's SecretStore directly.
// The root-embedded cases (2-5), the keeper_e2e root-missing case and their
// helpers live in refresh_server_keys_root_e2e_test.go: they need a test root
// key or the unverified mode, which only a keeper_e2e build has. The release
// root-missing case is in refresh_server_keys_release_test.go.
package handlers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

// bootstrapServerKeyVersionForTest mirrors the unexported keychain.bootstrapServerKeyVersion
// (the immutable v1 anchor). Tests reference it for slot-cleanup symmetry.
const bootstrapServerKeyVersionForTest uint = 1

// resetServerKeySlots clears all server-key-related Keychain slots between
// refresh_server_keys_test cases. Operates on the test's SecretStore directly.
func resetServerKeySlots(t *testing.T, store keychain.SecretStore) {
	t.Helper()
	for version := 1; version <= 3; version++ {
		_ = store.Delete(config.Service, fmt.Sprintf("%s%d", config.DragPassServerPublicKeyVersionedPrefix, version))
	}
	// active version pointer + root pubkey fingerprint also reset
	_ = store.Delete(config.Service, config.DragPassServerPublicKeyActiveVersion)
	_ = store.Delete(config.Service, config.DragPassServerRootPublicKeyFingerprint)
}

func TestRefreshServerKeysRequest_Validate(t *testing.T) {
	cases := []struct {
		name string
		req  RefreshServerKeysRequest
		want string
	}{
		{
			name: "empty",
			req:  RefreshServerKeysRequest{},
			want: "keys is empty",
		},
		{
			name: "no active",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p", Status: "deprecated"},
				},
			},
			want: "exactly one active key, got 0",
		},
		{
			name: "two active",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p1", Status: "active"},
					{Version: 2, PublicKeyPEM: "p2", Status: "active"},
				},
			},
			want: "exactly one active key, got 2",
		},
		{
			name: "version 0",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 0, PublicKeyPEM: "p", Status: "active"},
				},
			},
			want: "version must be >= 1",
		},
		{
			name: "empty pem",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "", Status: "active"},
				},
			},
			want: "public_key_pem is empty",
		},
		{
			name: "bad status",
			req: RefreshServerKeysRequest{
				Keys: []SystemServerKeyEntry{
					{Version: 1, PublicKeyPEM: "p", Status: "revoked"},
				},
			},
			want: "status invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}
