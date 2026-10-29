package onlineauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"
)

const decisionLifetime = 15 * time.Second
const maxPending = 4096

var ErrRefused = errors.New("current online authorization required")

type Identity struct {
	AccountID         string
	DeviceID          string
	SessionStartNanos int64
	AppBinding        string
	ConversationID    string
	OrgID             string
	LocalSession      string
	LoginGeneration   string
}

type Decision struct {
	Action            string `json:"action"`
	Challenge         string `json:"challenge"`
	Commitment        string `json:"commitment"`
	AccountID         string `json:"account_id"`
	DeviceID          string `json:"device_id"`
	SessionStartNanos int64  `json:"session_start_nanos,string"`
	AppBinding        string `json:"app_binding"`
	ConversationID    string `json:"conversation_id"`
	OrgID             string `json:"org_id"`
	IssuedAtMs        int64  `json:"issued_at_ms"`
	ExpiresAtMs       int64  `json:"expires_at_ms"`
	ServerKeyVersion  uint   `json:"server_key_version"`
	Signature         string `json:"signature"`
}

func (d Decision) Canonical() string {
	field := func(s string) string { return strconv.Itoa(len(s)) + ":" + s }
	return "dragpass.keeper.online.chat|1|" + field(d.Action) + "|" + field(d.Challenge) + "|" +
		field(d.Commitment) + "|" + field(d.AccountID) + "|" + field(d.DeviceID) + "|" +
		strconv.FormatInt(d.SessionStartNanos, 10) + "|" + field(d.AppBinding) + "|" +
		field(d.ConversationID) + "|" + field(d.OrgID) + "|" +
		strconv.FormatInt(d.IssuedAtMs, 10) + "|" + strconv.FormatInt(d.ExpiresAtMs, 10) + "|" +
		strconv.FormatUint(uint64(d.ServerKeyVersion), 10)
}

type signatureVerifier interface {
	Verify(string, string, uint) error
}
type pending struct {
	identity   Identity
	action     string
	commitment string
	created    time.Time
}

// Gate keeps only locally minted challenges. A process restart discards them.
type Gate struct {
	mu       sync.Mutex
	secret   [32]byte
	verifier signatureVerifier
	now      func() time.Time
	pending  map[string]pending
}

func New(v signatureVerifier, now func() time.Time) (*Gate, error) {
	if v == nil || now == nil {
		return nil, ErrRefused
	}
	g := &Gate{verifier: v, now: now, pending: make(map[string]pending)}
	if _, err := io.ReadFull(rand.Reader, g.secret[:]); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Gate) commitment(action string, request []byte) string {
	mac := hmac.New(sha256.New, g.secret[:])
	mac.Write([]byte("dragpass.keeper.online.request|1|"))
	mac.Write([]byte(strconv.Itoa(len(action))))
	mac.Write([]byte{':'})
	mac.Write([]byte(action))
	mac.Write([]byte{0})
	mac.Write(request)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *Gate) Prepare(action string, request []byte, identity Identity) (string, string, error) {
	if action == "" || identity.AccountID == "" || identity.DeviceID == "" ||
		identity.AppBinding == "" ||
		identity.ConversationID == "" || identity.OrgID == "" ||
		identity.LocalSession == "" || identity.LoginGeneration == "" {
		return "", "", ErrRefused
	}
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw[:])
	commitment := g.commitment(action, request)
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, item := range g.pending {
		if !g.now().Before(item.created.Add(decisionLifetime)) {
			delete(g.pending, key)
		}
	}
	if len(g.pending) >= maxPending {
		return "", "", ErrRefused
	}
	g.pending[challenge] = pending{identity: identity, action: action, commitment: commitment, created: g.now()}
	return challenge, commitment, nil
}

func (g *Gate) VerifyAndConsume(decision Decision, action string, request []byte, identity Identity) error {
	g.mu.Lock()
	item, found := g.pending[decision.Challenge]
	delete(g.pending, decision.Challenge)
	g.mu.Unlock()
	if !found || !g.now().Before(item.created.Add(decisionLifetime)) ||
		item.identity != identity || item.action != action || decision.Action != action ||
		!hmac.Equal([]byte(item.commitment), []byte(decision.Commitment)) ||
		!hmac.Equal([]byte(g.commitment(action, request)), []byte(decision.Commitment)) ||
		decision.AccountID != identity.AccountID || decision.DeviceID != identity.DeviceID ||
		decision.SessionStartNanos <= 0 ||
		(identity.SessionStartNanos != 0 && decision.SessionStartNanos != identity.SessionStartNanos) ||
		decision.AppBinding != identity.AppBinding ||
		decision.ConversationID != identity.ConversationID || decision.OrgID != identity.OrgID ||
		decision.ServerKeyVersion == 0 || decision.Signature == "" {
		return ErrRefused
	}
	nowMs := g.now().UnixMilli()
	if decision.IssuedAtMs > nowMs+5000 || decision.ExpiresAtMs-decision.IssuedAtMs != decisionLifetime.Milliseconds() ||
		nowMs >= decision.ExpiresAtMs || decision.IssuedAtMs < item.created.UnixMilli()-5000 {
		return ErrRefused
	}
	if g.verifier.Verify(decision.Canonical(), decision.Signature, decision.ServerKeyVersion) != nil {
		return ErrRefused
	}
	return nil
}
