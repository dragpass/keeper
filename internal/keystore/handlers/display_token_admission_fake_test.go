package handlers

import (
	"errors"
	"strconv"
	"strings"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// testDisplayTokens stands in for a future authenticated-expiry token format.
// It exists only in tests; production Deps leave DisplayTokens nil.
type testDisplayTokens struct{}

func (testDisplayTokens) AdmitTokenContext(scope string, aad []byte) (proto.DisplayTokenContext, error) {
	parts := strings.Split(string(aad), "|")
	if len(parts) != 6 || parts[0] != "test.display-token" || parts[1] != scope {
		return proto.DisplayTokenContext{}, errors.New("unadmitted test token")
	}
	version, err := strconv.Atoi(parts[2])
	if err != nil {
		return proto.DisplayTokenContext{}, err
	}
	expiry, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return proto.DisplayTokenContext{}, err
	}
	return proto.DisplayTokenContext{Scope: scope, DekVersion: version, OrgID: parts[3], GroupID: parts[4], ExpiresAt: expiry}, nil
}

func (testDisplayTokens) AdmitAuditToken() error { return nil }
