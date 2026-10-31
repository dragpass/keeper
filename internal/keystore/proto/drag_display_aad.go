package proto

import (
	"errors"
	"strconv"
	"strings"
)

var errInvalidDragDisplayAAD = errors.New("invalid authenticated drag display context")

type DragDisplayAAD struct {
	Scope      string
	DekVersion int
	OrgID      string
	GroupID    string
	ExpiresAt  int64
	EntryRef   string
}

// ParseDragDisplayAAD accepts only the canonical context used by new drag
// tokens. The AEAD tag authenticates these bytes; the caller checks expiry
// and compares scope with its current local key before opening ciphertext.
func ParseDragDisplayAAD(raw []byte) (DragDisplayAAD, error) {
	var out DragDisplayAAD
	if len(raw) == 0 || len(raw) > 256 {
		return out, errInvalidDragDisplayAAD
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 8 || parts[0] != "dragpass.drag-display" || parts[1] != "1" {
		return out, errInvalidDragDisplayAAD
	}
	version, err := strconv.ParseInt(parts[3], 10, 32)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != parts[3] {
		return out, errInvalidDragDisplayAAD
	}
	expiry, err := strconv.ParseInt(parts[6], 10, 64)
	if err != nil || expiry < 0 || len(parts[6]) > 11 || strconv.FormatInt(expiry, 10) != parts[6] {
		return out, errInvalidDragDisplayAAD
	}
	if parts[7] != "" {
		if len(parts[7]) != 26 {
			return out, errInvalidDragDisplayAAD
		}
		for _, c := range parts[7] {
			if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
				return out, errInvalidDragDisplayAAD
			}
		}
	}
	switch parts[2] {
	case "personal":
		if parts[4] != "" || parts[5] != "" || version != 1 {
			return out, errInvalidDragDisplayAAD
		}
	case "group":
		if requireMessageUUID(parts[4], "org_id") != nil ||
			(parts[5] != "" && requireMessageUUID(parts[5], "group_id") != nil) {
			return out, errInvalidDragDisplayAAD
		}
	default:
		return out, errInvalidDragDisplayAAD
	}
	return DragDisplayAAD{
		Scope: parts[2], DekVersion: int(version), OrgID: parts[4], GroupID: parts[5],
		ExpiresAt: expiry, EntryRef: parts[7],
	}, nil
}
