//go:build keeper_e2e && keeper_e2e_localtarget

package handlers

import (
	"crypto/x509"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// This file exists only in a build with both the keeper_e2e and the
// keeper_e2e_localtarget tags (make build-e2e-localtarget). It lets a
// real-stack verification send an approved credential request to a local HTTPS
// test server:
//
//   - KEEPER_E2E_LOCAL_TARGET_PORTS — comma-separated ports. A connection is
//     allowed when its resolved address is loopback and its port is listed.
//     No other address class and no other port; an empty list allows nothing.
//   - KEEPER_E2E_LOCAL_TARGET_CA_FILE — a PEM file added to a copy of the
//     system roots. TLS verification stays on; without the file only the
//     system roots apply.
//
// Signature verification, nonce consumption, and the target, query and body
// checks run before any dial and are not touched here. A release build has a
// stub that allows nothing (credential_localtarget_release.go) and refuses to
// start with any KEEPER_E2E_* variable set.

const (
	localTargetPortsEnvVar  = "KEEPER_E2E_LOCAL_TARGET_PORTS"
	localTargetCAFileEnvVar = "KEEPER_E2E_LOCAL_TARGET_CA_FILE"
)

type localTargetConfig struct {
	ports map[int]bool
	roots *x509.CertPool
}

var (
	localTargetMu     sync.Mutex
	localTargetLoaded *localTargetConfig
)

func currentLocalTargetConfig() *localTargetConfig {
	localTargetMu.Lock()
	defer localTargetMu.Unlock()
	if localTargetLoaded == nil {
		localTargetLoaded = loadLocalTargetConfig(os.Getenv)
	}
	return localTargetLoaded
}

func loadLocalTargetConfig(getenv func(string) string) *localTargetConfig {
	cfg := &localTargetConfig{ports: map[int]bool{}}
	for _, field := range strings.Split(getenv(localTargetPortsEnvVar), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(field)); err == nil && n >= 1 && n <= 65535 {
			cfg.ports[n] = true
		}
	}
	if path := strings.TrimSpace(getenv(localTargetCAFileEnvVar)); path != "" {
		pemBytes, err := os.ReadFile(path)
		if err == nil {
			roots, sysErr := x509.SystemCertPool()
			if sysErr != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			// An unreadable or empty file adds nothing, and then the local
			// server's certificate simply fails verification.
			if roots.AppendCertsFromPEM(pemBytes) {
				cfg.roots = roots
			}
		}
	}
	return cfg
}

func localTargetDialAllowed(ip net.IP, port int) bool {
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return currentLocalTargetConfig().ports[port]
}

func localTargetRootCAs() *x509.CertPool {
	return currentLocalTargetConfig().roots
}

// resetLocalTargetConfigForTest makes the next call read the environment again.
func resetLocalTargetConfigForTest() {
	localTargetMu.Lock()
	defer localTargetMu.Unlock()
	localTargetLoaded = nil
}
