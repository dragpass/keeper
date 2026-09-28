package localrpc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// testAppClient speaks the App side of the local RPC over real HTTP, the way
// dragpass app/src/shared/keeper/local-keeper-client.ts does.
type testAppClient struct {
	address    string
	origin     string
	pairingKey []byte
	session    string
	csrf       string
	sessionKey []byte
	// epoch is the chat runtime epoch last granted, sent on every request.
	epoch string
}

func (c *testAppClient) do(method, path string, body []byte, withSession bool) (*http.Response, error) {
	request, err := http.NewRequest(method, "http://"+c.address+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Origin", c.origin)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("X-DragPass-Local-RPC", "1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if withSession {
		request.Header.Set("Authorization", "Bearer "+c.session)
		request.Header.Set("X-DragPass-CSRF", c.csrf)
		if c.epoch != "" {
			request.Header.Set(chatRuntimeEpochHeader, c.epoch)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	return client.Do(request)
}

func (c *testAppClient) postJSON(path string, body any, withSession bool, into any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	response, err := c.do(http.MethodPost, path, raw, withSession)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", path, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(into)
}

// open runs the challenge, proves the pairing key and checks the owner proof
// before anything secret is sent.
func (c *testAppClient) open() error {
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	if err := c.postJSON("/v1/session/challenge", map[string]string{}, false, &challenge); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	clientNonce := base64.RawURLEncoding.EncodeToString(nonce)
	var opened struct {
		Session    string `json:"session"`
		CSRF       string `json:"csrf"`
		ExpiresAt  int64  `json:"expires_at"`
		OwnerProof string `json:"owner_proof"`
	}
	if err := c.postJSON("/v1/session", map[string]string{
		"challenge":    challenge.Challenge,
		"client_nonce": clientNonce,
		"proof":        macB64(c.pairingKey, appOpenLabel, c.origin, challenge.Challenge, clientNonce),
	}, false, &opened); err != nil {
		return err
	}
	expected := mac(c.pairingKey, appOwnerLabel, c.origin, challenge.Challenge, clientNonce,
		opened.Session, opened.CSRF, strconv.FormatInt(opened.ExpiresAt, 10))
	if !equalMAC(expected, opened.OwnerProof) {
		return errors.New("owner proof does not verify")
	}
	c.session, c.csrf = opened.Session, opened.CSRF
	c.sessionKey = appSessionKey(c.pairingKey, c.origin, challenge.Challenge, clientNonce, opened.Session, opened.CSRF, opened.ExpiresAt)
	return nil
}

// call seals one App request to the owner that proved itself and accepts only
// an answer sealed back to this request.
func (c *testAppClient) call(path string, body any) (proto.BaseResponse, error) {
	var envelope proto.BaseResponse
	plain, err := json.Marshal(body)
	if err != nil {
		return envelope, err
	}
	sealed, err := sealEnvelope(c.sessionKey, appRequestAAD(c.origin, c.session, path), plain)
	if err != nil {
		return envelope, err
	}
	var answer sealedEnvelope
	if err := c.postJSON(path, sealed, true, &answer); err != nil {
		return envelope, err
	}
	opened, err := openEnvelope(c.sessionKey, answer, appResponseAAD(c.origin, c.session, path, sealed.Nonce))
	if err != nil {
		return envelope, errors.New("the answer was not sealed by the owner this session proved")
	}
	err = json.Unmarshal(opened, &envelope)
	return envelope, err
}

// claim takes the chat runtime lease for holder and keeps the epoch it was
// granted.
func (c *testAppClient) claim(holder string) (proto.BaseResponse, error) {
	response, err := c.call("/v1/chat/runtime/claim", map[string]string{"holder_id": holder})
	if err == nil && response.Success {
		raw, _ := json.Marshal(response.Data)
		c.epoch = epochOf(raw)
	}
	return response, err
}

func (c *testAppClient) status() (proto.BaseResponse, error) {
	return c.call("/v1/status", map[string]string{})
}
