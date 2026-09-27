package localrpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// The loopback port is reachable by every OS user on the machine and a
// non-browser process can send any Origin it likes, so both local channels are
// authenticated with keys derived from the owner-only local secret:
//
//   - App sessions open only after a challenge-response proof with the pairing
//     key, and the owner proves itself back before the App sends a password.
//     Every request in the session is then AES-GCM sealed under a key derived
//     from the pairing key and that session's transcript, so a process that
//     takes the port after the owner exits reads nothing and cannot answer.
//   - Native Messaging proxy traffic is AES-GCM sealed to one proven owner
//     instance, so a process that grabbed the port learns nothing and cannot
//     replay a request to the next owner.

const (
	proxyClockSkew     = 60 * time.Second
	maxProxyNonces     = 4096
	appChallengeTTL    = 30 * time.Second
	maxAppChallenges   = 64
	appOpenLabel       = "dragpass-keeper-app-open-v1"
	appOwnerLabel      = "dragpass-keeper-app-owner-v1"
	appSessionKeyLabel = "dragpass-keeper-app-session-key-v1"
	appRequestLabel    = "dragpass-keeper-app-request-v1"
	appResponseLabel   = "dragpass-keeper-app-response-v1"
	proxyHealthLabel   = "dragpass-keeper-native-proxy-health-v2"
	proxyRequestLabel  = "dragpass-keeper-native-proxy-request-v2"
	proxyResponseLabel = "dragpass-keeper-native-proxy-response-v2"
)

var (
	errStaleProxyInstance = errors.New("native proxy request addressed another owner instance")
	errProxyRejected      = errors.New("native proxy request rejected")
)

type sealedEnvelope struct {
	Instance  string `json:"instance,omitempty"`
	Timestamp int64  `json:"ts,omitempty"`
	Nonce     string `json:"nonce"`
	Sealed    string `json:"ct"`
}

func mac(key []byte, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	for i, part := range parts {
		if i > 0 {
			h.Write([]byte{'\n'})
		}
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

func macB64(key []byte, parts ...string) string {
	return base64.RawURLEncoding.EncodeToString(mac(key, parts...))
}

func equalMAC(expected []byte, providedB64 string) bool {
	provided, err := base64.RawURLEncoding.DecodeString(providedB64)
	return err == nil && hmac.Equal(expected, provided)
}

func validNonce(value string, minBytes int) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) >= minBytes && len(value) <= 128
}

func newAEAD(proxyKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(mac(proxyKey, "aead"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// appSessionKey is known only to the owner that opened the session and the App
// that checked its owner proof: both need the pairing key and the transcript.
func appSessionKey(appKey []byte, origin, challenge, clientNonce, session, csrf string, expiresAt int64) []byte {
	return mac(appKey, appSessionKeyLabel, origin, challenge, clientNonce, session, csrf, strconv.FormatInt(expiresAt, 10))
}

func appRequestAAD(origin, session, path string) []byte {
	return []byte(appRequestLabel + "\n" + origin + "\n" + session + "\n" + path)
}

func appResponseAAD(origin, session, path, requestNonce string) []byte {
	return []byte(appResponseLabel + "\n" + origin + "\n" + session + "\n" + path + "\n" + requestNonce)
}

func sealEnvelope(key []byte, aad, plain []byte) (sealedEnvelope, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return sealedEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return sealedEnvelope{}, err
	}
	return sealedEnvelope{
		Nonce:  base64.RawURLEncoding.EncodeToString(nonce),
		Sealed: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad)),
	}, nil
}

func healthProof(proxyKey []byte, challenge, instance string) []byte {
	return mac(mac(proxyKey, "health"), proxyHealthLabel, challenge, instance)
}

func sealProxyRequest(proxyKey []byte, instance string, now time.Time, message []byte) ([]byte, string, error) {
	aead, err := newAEAD(proxyKey)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	ts := now.Unix()
	aad := []byte(proxyRequestLabel + "\n" + instance + "\n" + strconv.FormatInt(ts, 10))
	envelope := sealedEnvelope{
		Instance:  instance,
		Timestamp: ts,
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		Sealed:    base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, message, aad)),
	}
	body, err := json.Marshal(envelope)
	return body, envelope.Nonce, err
}

func sealProxyResponse(proxyKey []byte, instance, requestNonce string, response []byte) ([]byte, error) {
	aead, err := newAEAD(proxyKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(proxyResponseLabel + "\n" + instance + "\n" + requestNonce)
	return json.Marshal(sealedEnvelope{
		Nonce:  base64.RawURLEncoding.EncodeToString(nonce),
		Sealed: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, response, aad)),
	})
}

func openProxyResponse(proxyKey []byte, instance, requestNonce string, body []byte) ([]byte, error) {
	var envelope sealedEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errProxyRejected
	}
	aad := []byte(proxyResponseLabel + "\n" + instance + "\n" + requestNonce)
	return openEnvelope(proxyKey, envelope, aad)
}

func openEnvelope(proxyKey []byte, envelope sealedEnvelope, aad []byte) ([]byte, error) {
	aead, err := newAEAD(proxyKey)
	if err != nil {
		return nil, errProxyRejected
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errProxyRejected
	}
	sealed, err := base64.RawURLEncoding.DecodeString(envelope.Sealed)
	if err != nil {
		return nil, errProxyRejected
	}
	plain, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, errProxyRejected
	}
	return plain, nil
}

// proxyReceiver is the owner side of the sealed channel.
type proxyReceiver struct {
	key      []byte
	instance string
	mu       sync.Mutex
	seen     map[string]time.Time
}

func (p *proxyReceiver) open(body []byte, now time.Time) ([]byte, string, error) {
	var envelope sealedEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil ||
		envelope.Instance == "" || envelope.Nonce == "" || envelope.Sealed == "" {
		return nil, "", errProxyRejected
	}
	if envelope.Instance != p.instance {
		return nil, "", errStaleProxyInstance
	}
	if skew := now.Sub(time.Unix(envelope.Timestamp, 0)); skew > proxyClockSkew || skew < -proxyClockSkew {
		return nil, "", errProxyRejected
	}
	aad := []byte(proxyRequestLabel + "\n" + envelope.Instance + "\n" + strconv.FormatInt(envelope.Timestamp, 10))
	plain, err := openEnvelope(p.key, envelope, aad)
	if err != nil {
		return nil, "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for nonce, at := range p.seen {
		if now.Sub(at) > 2*proxyClockSkew {
			delete(p.seen, nonce)
		}
	}
	if _, replay := p.seen[envelope.Nonce]; replay || len(p.seen) >= maxProxyNonces {
		return nil, "", errProxyRejected
	}
	p.seen[envelope.Nonce] = now
	return plain, envelope.Nonce, nil
}
