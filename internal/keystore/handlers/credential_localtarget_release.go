//go:build !(keeper_e2e && keeper_e2e_localtarget)

package handlers

import (
	"crypto/x509"
	"net"
)

// Every build except keeper_e2e + keeper_e2e_localtarget: the HTTP sink dials
// no loopback address and trusts only the system roots.
// credential_localtarget_e2e.go holds the test-only opt-in.

func localTargetDialAllowed(net.IP, int) bool { return false }

func localTargetRootCAs() *x509.CertPool { return nil }
