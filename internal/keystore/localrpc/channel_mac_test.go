package localrpc

import (
	"net/http"
	"testing"
)

// mac joins its parts with '\n', which is unambiguous only while no part can
// carry one. Go's Base64 decoder skips '\r' and '\n', so a nonce check that
// only decodes would let a client nonce bring a separator into the MAC input.
func TestValidNonceAcceptsOnlyCanonicalBase64URL(t *testing.T) {
	if !validNonce(testClientNonce, 16) {
		t.Fatal("the canonical test nonce was refused")
	}
	for name, value := range map[string]string{
		"embedded newline":  testClientNonce[:10] + "\n" + testClientNonce[10:],
		"embedded CR":       testClientNonce[:10] + "\r" + testClientNonce[10:],
		"trailing newline":  testClientNonce + "\n",
		"padded":            testClientNonce + "=",
		"standard alphabet": "Y2xpZW50LW5vbmNlLTE2Ynl0ZXM+",
	} {
		if validNonce(value, 16) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpenSessionRefusesAClientNonceWithASeparator(t *testing.T) {
	server := newTestServer(t)
	challenge := requestAppChallenge(t, server)
	nonce := testClientNonce[:10] + "\n" + testClientNonce[10:]
	response := localRequest(server, http.MethodPost, "/v1/session", appOpenBody(server.appKey, testOrigin, challenge, nonce), "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("a client nonce with a newline opened a session: %d", response.Code)
	}
}
