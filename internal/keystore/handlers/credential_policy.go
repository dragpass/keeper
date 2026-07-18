package handlers

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const credentialPolicySignatureAlg = "rsa-pss-sha256"

func canonicalCredentialPolicy(p proto.CredentialPolicy) string {
	hosts := append([]string(nil), p.AllowedHosts...)
	methods := append([]string(nil), p.AllowedMethods...)
	paths := append([]string(nil), p.AllowedPathPatterns...)
	sort.Strings(hosts)
	sort.Strings(methods)
	sort.Strings(paths)
	return strings.Join([]string{
		p.EntryID,
		strconv.Itoa(p.DekVersion),
		strings.Join(hosts, ","),
		strings.Join(methods, ","),
		strings.Join(paths, ","),
		p.Expiry,
	}, "|")
}

func validateCredentialPolicyBinding(aad []byte, p proto.CredentialPolicy) error {
	parts := strings.Split(string(aad), "|")
	if len(parts) != 5 {
		return fmt.Errorf("credential AAD has invalid field count")
	}
	if parts[1] != p.EntryID {
		return fmt.Errorf("credential policy entry_id does not match AAD")
	}
	if parts[2] != "credential" || parts[3] != "1" {
		return fmt.Errorf("credential AAD payload kind or schema version is unsupported")
	}
	if parts[4] != strconv.Itoa(p.DekVersion) {
		return fmt.Errorf("credential policy dek_version does not match AAD")
	}
	return nil
}

func verifyCredentialPolicy(d Deps, aad []byte, p proto.CredentialPolicy) (bool, proto.BaseResponse) {
	if p.SignatureAlg != credentialPolicySignatureAlg {
		return false, errs.CodeResponse(errs.ErrCodeValidation, "unsupported credential policy signature algorithm")
	}
	expires, err := time.Parse(time.RFC3339, p.Expiry)
	if err != nil {
		return false, errs.CodeResponse(errs.ErrCodeValidation, "credential policy expiry is invalid")
	}
	if !expires.After(d.Now().UTC()) {
		return false, errs.CodeResponse(errs.ErrCodeCryptoFailure, "credential policy has expired")
	}
	if err := validateCredentialPolicyBinding(aad, p); err != nil {
		return false, errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	return verifyServerSig(d, canonicalCredentialPolicy(p), p.Signature, p.ServerKeyVersion, "credential policy")
}
