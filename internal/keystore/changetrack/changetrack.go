// Package changetrack tells whether an entry's value changed without keeping
// the value.
//
// Keeper seals, for each value version of an entry, a comparison record:
//
//	record plaintext = 0x01 || K (32 random bytes) || tag (32 bytes)
//	tag              = HMAC-SHA256(K, tagDomain || L(kind) || L(scope_id) || L(group_id) || L(entry_id) || value)
//	record AAD       = dragpass.drag.change|1|<kind>|<scope_id>|<group_id or ->|<entry_id>|<dek_version>|<seq>
//
// The record is AES-256-GCM sealed under the DEK of dek_version. K is fresh
// for every record, so two entries, or two versions of one entry, holding the
// same value have unrelated tags, and the comparison key never outlives the
// value version it describes. The DEK only wraps the record; its rotation does
// not touch K.
//
// Only the sealed bytes and a verdict leave this package. K, the tag and the
// value never do. A record that cannot be verified gives VerdictUnknown, never
// VerdictChanged.
//
// The AAD domain starts with "dragpass.drag.", which proto.ReservedAADDomains
// refuses for every caller-chosen AAD, so no caller can mint a record through
// the generic seal actions.
//
// Contract: docs/protocol.md "Entry value-change tracking".
package changetrack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// Scope kinds.
const (
	ScopeGroup    = "group"
	ScopePersonal = "personal"
)

// AADDomain is the record AAD domain.
const AADDomain = "dragpass.drag.change"

const (
	recordSchema   = "1"
	recordFormatV1 = 0x01
	recordKeyBytes = 32
	recordTagBytes = sha256.Size
	recordBytes    = 1 + recordKeyBytes + recordTagBytes
	tagDomain      = "dragpass.drag.change.tag|1|"
	noGroup        = "-"
	dekKeyBytes    = 32
)

// Verdict is the only comparison result that leaves Keeper.
type Verdict string

const (
	// VerdictBaseline — no previous record; a first baseline was set.
	VerdictBaseline Verdict = "baseline"
	// VerdictSame — the previous record verified and the value matches it.
	VerdictSame Verdict = "same"
	// VerdictChanged — the previous record verified and the value differs.
	VerdictChanged Verdict = "changed"
	// VerdictUnknown — a previous record was given but could not be verified.
	VerdictUnknown Verdict = "unknown"
)

// Scope names the entry a record belongs to. ScopeID is the org id for a
// Group entry and the Keeper's signed-in account binding for a personal one.
// GroupID is empty for a personal entry.
type Scope struct {
	Kind    string
	ScopeID string
	GroupID string
	EntryID string
}

// Sealed is a comparison record as stored by the server. Every field is
// opaque or public context; none of it is secret on its own.
type Sealed struct {
	IV         []byte
	Ciphertext []byte
	DekVersion int
	Seq        uint64
}

// ErrInvalidScope — a scope or version field is malformed.
var ErrInvalidScope = errors.New("invalid change-tracking scope")

// Seal creates the record for value under dek.
func Seal(random io.Reader, dek []byte, s Scope, dekVersion int, seq uint64, value []byte) (Sealed, error) {
	aad, err := recordAAD(s, dekVersion, seq)
	if err != nil {
		return Sealed{}, err
	}
	key := make([]byte, recordKeyBytes)
	defer secure.Zeroize(key)
	if _, err := io.ReadFull(random, key); err != nil {
		return Sealed{}, errors.New("change record key generation failed")
	}
	plain := make([]byte, 0, recordBytes)
	defer func() { secure.Zeroize(plain[:cap(plain)]) }()
	plain = append(plain, recordFormatV1)
	plain = append(plain, key...)
	plain = append(plain, valueTag(key, s, value)...)
	iv, ct, err := crypto.SealAESGCM(random, dek, plain, aad)
	if err != nil {
		return Sealed{}, errors.New("change record seal failed")
	}
	return Sealed{IV: iv, Ciphertext: ct, DekVersion: dekVersion, Seq: seq}, nil
}

// Compare checks value against prev. Any failure to verify prev, including a
// wrong scope, DEK version or sequence, damaged bytes or an unsupported
// format, is VerdictUnknown.
func Compare(dek []byte, s Scope, prev Sealed, value []byte) Verdict {
	aad, err := recordAAD(s, prev.DekVersion, prev.Seq)
	if err != nil || len(dek) != dekKeyBytes {
		return VerdictUnknown
	}
	plain, err := crypto.OpenAESGCM(dek, prev.IV, prev.Ciphertext, aad)
	if err != nil {
		return VerdictUnknown
	}
	defer secure.Zeroize(plain)
	if len(plain) != recordBytes || plain[0] != recordFormatV1 {
		return VerdictUnknown
	}
	key := plain[1 : 1+recordKeyBytes]
	want := plain[1+recordKeyBytes:]
	got := valueTag(key, s, value)
	defer secure.Zeroize(got)
	if hmac.Equal(got, want) {
		return VerdictSame
	}
	return VerdictChanged
}

func valueTag(key []byte, s Scope, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tagDomain))
	for _, f := range []string{s.Kind, s.ScopeID, s.GroupID, s.EntryID} {
		writeLen(mac, len(f))
		mac.Write([]byte(f))
	}
	mac.Write(value)
	return mac.Sum(nil)
}

func writeLen(w io.Writer, n int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	w.Write(b[:])
}

func recordAAD(s Scope, dekVersion int, seq uint64) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if dekVersion < 1 || seq < 1 {
		return nil, ErrInvalidScope
	}
	group := s.GroupID
	if s.Kind == ScopePersonal {
		group = noGroup
	}
	return []byte(strings.Join([]string{
		AADDomain, recordSchema, s.Kind, s.ScopeID, group, s.EntryID,
		strconv.Itoa(dekVersion), strconv.FormatUint(seq, 10),
	}, "|")), nil
}

func (s Scope) validate() error {
	switch s.Kind {
	case ScopeGroup:
		if !isCanonicalUUID(s.GroupID) {
			return ErrInvalidScope
		}
	case ScopePersonal:
		if s.GroupID != "" {
			return ErrInvalidScope
		}
	default:
		return ErrInvalidScope
	}
	if !isCanonicalUUID(s.ScopeID) || !isCanonicalUUID(s.EntryID) {
		return ErrInvalidScope
	}
	return nil
}

// isCanonicalUUID accepts the lowercase 8-4-4-4-12 form only, so one entry has
// exactly one AAD spelling.
func isCanonicalUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
