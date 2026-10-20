package handlers

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// localTargetServer is a loopback TLS server that counts connections and
// requests, with its certificate written to a PEM file usable as a test CA.
type localTargetServer struct {
	url    string
	port   int
	caFile string
	conns  atomic.Int32
	hits   atomic.Int32
}

func newLocalTargetServer(t *testing.T) *localTargetServer {
	t.Helper()
	s := &localTargetServer{}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.conns.Add(1)
		}
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	s.url = ts.URL
	_, portText, _ := net.SplitHostPort(ts.Listener.Addr().String())
	s.port, _ = strconv.Atoi(portText)
	s.caFile = filepath.Join(t.TempDir(), "test-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(s.caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return s
}

// localTargetRequest is a well-formed signed request for s with no test TLS
// hook and no loopback seam: only the build's own rules decide.
func localTargetRequest(t *testing.T, deps Deps, s *localTargetServer) proto.CredentialHTTPRequest {
	t.Helper()
	handle, groupRaw := openSessionForFreshKey(t, deps)
	credJSON := `{"type":"api_token","label":"t","secret":{"token":"SUPER_SECRET_TOKEN_XYZ"}}`
	ivB64, ctB64, aadB64 := sealCredentialForTest(t, groupRaw, credJSON, credTestAAD)
	policy := credTestPolicy([]string{hostOf(t, s.url)}, []string{"GET"})
	return proto.CredentialHTTPRequest{
		GroupHandle:    handle,
		IVB64:          ivB64,
		CiphertextB64:  ctB64,
		AADB64:         aadB64,
		TargetURL:      s.url + "/x",
		Method:         "GET",
		HeaderTemplate: policy.HeaderTemplate,
		Policy:         policy,
	}
}

func requireNoLocalTargetSeams(t *testing.T) {
	t.Helper()
	if testTLSConfigHook != nil || testAllowLoopbackDial {
		t.Fatal("a test seam is set; these tests must run on the build's own rules")
	}
}
