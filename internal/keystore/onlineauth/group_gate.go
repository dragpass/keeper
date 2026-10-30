package onlineauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strconv"
	"sync"
	"time"
)

type GroupIdentity struct {
	TokenID         string
	AccountID       string
	DeviceID        string
	OrgID           string
	GroupID         string
	DEKVersion      int
	GrantPolicy     string
	GrantDigest     string
	LocalGeneration uint64
}

type GroupDecision struct {
	TokenID           string `json:"token_id"`
	Action            string `json:"action"`
	Challenge         string `json:"challenge"`
	Commitment        string `json:"commitment"`
	AccountID         string `json:"account_id"`
	DeviceID          string `json:"device_id"`
	SessionStartNanos int64  `json:"session_start_nanos,string"`
	Client            string `json:"client"`
	OrgID             string `json:"org_id"`
	GroupID           string `json:"group_id"`
	DEKVersion        int    `json:"dek_version"`
	GrantPolicy       string `json:"grant_policy"`
	GrantDigest       string `json:"grant_digest"`
	IssuedAtMs        int64  `json:"issued_at_ms"`
	ExpiresAtMs       int64  `json:"expires_at_ms"`
	ServerKeyVersion  uint   `json:"server_key_version"`
	Signature         string `json:"signature"`
}

func (d GroupDecision) Canonical() string {
	field := func(s string) string { return strconv.Itoa(len(s)) + ":" + s }
	return "dragpass.keeper.online.group|1|" + field(d.Action) + "|" + field(d.Challenge) + "|" +
		field(d.Commitment) + "|" + field(d.AccountID) + "|" + field(d.DeviceID) + "|" +
		strconv.FormatInt(d.SessionStartNanos, 10) + "|" + field(d.TokenID) + "|" + field(d.Client) + "|" +
		field(d.OrgID) + "|" + field(d.GroupID) + "|" + strconv.Itoa(d.DEKVersion) + "|" +
		field(d.GrantPolicy) + "|" + field(d.GrantDigest) + "|" +
		strconv.FormatInt(d.IssuedAtMs, 10) + "|" + strconv.FormatInt(d.ExpiresAtMs, 10) + "|" +
		strconv.FormatUint(uint64(d.ServerKeyVersion), 10)
}

type groupPending struct {
	identity   GroupIdentity
	action     string
	commitment string
	created    time.Time
}

// GroupGate retains only Keeper-minted request challenges in this process.
// The local identity is provenance; the signed server decision supplies authority.
type GroupGate struct {
	mu       sync.Mutex
	secret   [32]byte
	verifier signatureVerifier
	now      func() time.Time
	pending  map[string]groupPending
}

func NewGroup(v signatureVerifier, now func() time.Time) (*GroupGate, error) {
	if v == nil || now == nil {
		return nil, ErrRefused
	}
	g := &GroupGate{verifier: v, now: now, pending: make(map[string]groupPending)}
	if _, err := io.ReadFull(rand.Reader, g.secret[:]); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *GroupGate) commitment(action string, request []byte) string {
	mac := hmac.New(sha256.New, g.secret[:])
	mac.Write([]byte("dragpass.keeper.online.group.request|1|"))
	mac.Write([]byte(strconv.Itoa(len(action))))
	mac.Write([]byte{':'})
	mac.Write([]byte(action))
	mac.Write([]byte{0})
	mac.Write(request)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *GroupGate) Prepare(action string, request []byte, id GroupIdentity) (string, string, error) {
	if g == nil || action == "" || id.TokenID == "" || id.AccountID == "" || id.DeviceID == "" || id.OrgID == "" ||
		id.GroupID == "" || id.DEKVersion <= 0 || id.GrantPolicy == "" || id.GrantDigest == "" || id.LocalGeneration == 0 {
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
	g.pending[challenge] = groupPending{identity: id, action: action, commitment: commitment, created: g.now()}
	return challenge, commitment, nil
}

func (g *GroupGate) VerifyAndConsume(d GroupDecision, action string, request []byte, id GroupIdentity) error {
	if g == nil {
		return ErrRefused
	}
	g.mu.Lock()
	item, found := g.pending[d.Challenge]
	delete(g.pending, d.Challenge)
	g.mu.Unlock()
	if !found || !g.now().Before(item.created.Add(decisionLifetime)) || item.identity != id ||
		item.action != action || d.Action != action || d.Client != "extension" || d.SessionStartNanos <= 0 || d.TokenID != id.TokenID ||
		d.AccountID != id.AccountID || d.DeviceID != id.DeviceID || d.OrgID != id.OrgID || d.GroupID != id.GroupID ||
		d.DEKVersion != id.DEKVersion || d.GrantPolicy != id.GrantPolicy || d.GrantDigest != id.GrantDigest ||
		!hmac.Equal([]byte(item.commitment), []byte(d.Commitment)) ||
		!hmac.Equal([]byte(g.commitment(action, request)), []byte(d.Commitment)) || d.ServerKeyVersion == 0 || d.Signature == "" {
		return ErrRefused
	}
	nowMs := g.now().UnixMilli()
	if d.IssuedAtMs > nowMs+5000 || d.ExpiresAtMs-d.IssuedAtMs != decisionLifetime.Milliseconds() ||
		nowMs >= d.ExpiresAtMs || d.IssuedAtMs < item.created.UnixMilli()-5000 {
		return ErrRefused
	}
	if g.verifier.Verify(d.Canonical(), d.Signature, d.ServerKeyVersion) != nil {
		return ErrRefused
	}
	return nil
}
