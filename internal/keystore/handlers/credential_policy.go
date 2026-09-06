package handlers

import (
	"fmt"
	"net/url"
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
	parts := []string{
		p.EntryID,
		strconv.Itoa(p.DekVersion),
		strings.Join(hosts, ","),
		strings.Join(methods, ","),
		strings.Join(paths, ","),
		canonicalCredentialHeaders(p.HeaderTemplate),
		strconv.FormatBool(p.AllowQuery),
		strconv.FormatBool(p.AllowBody),
		p.TargetHost,
		p.TargetPath,
		p.Method,
		p.Expiry,
	}
	// Both trailing blocks are appended only when their template is non-empty, so
	// every policy that injects into headers or cookies canonicalizes to exactly
	// the bytes it did before either field existed — a signature made by a server
	// that predates them still verifies. The slots are unambiguous: expiry is
	// RFC3339 (validated by time.Parse before this is called) and cannot contain
	// "|", the template encodings are length-prefixed and self-delimiting, and a
	// policy injects into exactly one place, so query and exec are never both
	// present.
	if len(p.QueryTemplate) > 0 {
		parts = append(parts, canonicalCredentialHeaders(p.QueryTemplate))
	}
	if len(p.EnvTemplate) > 0 {
		parts = append(parts,
			p.ExecExecutable,
			canonicalCredentialArgv(p.ExecArgv),
			p.ExecCwd,
			canonicalCredentialHeaders(p.EnvTemplate),
		)
	}
	return strings.Join(parts, "|")
}

// canonicalCredentialArgv encodes argv as length-prefixed elements joined with
// ",". The length prefixes make the encoding injective the same way the template
// encoding is: no combination of arguments can be re-read as a different argv,
// and an argument containing "," or "|" cannot forge a field boundary.
//
// ariadne's credential/sign.go carries a byte-identical function. If the two
// ever disagree by one character, every exec resolve fails signature
// verification — which is why both repos assert the same literal for a shared
// fixture.
func canonicalCredentialArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		parts = append(parts, strconv.Itoa(len(arg))+":"+arg)
	}
	return strings.Join(parts, ",")
}

func executionTargetMatches(targetURL, method string, p proto.CredentialPolicy) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return normalizeHost(u.Host) == normalizeHost(p.TargetHost) &&
		path == p.TargetPath && strings.EqualFold(strings.TrimSpace(method), strings.TrimSpace(p.Method))
}

// canonicalCredentialHeaders encodes a {name: value} template as a
// length-prefixed, key-sorted string. Both header_template and query_template
// use it — the length prefixes make the encoding injective, so no combination of
// names and values can be re-read as a different map.
func canonicalCredentialHeaders(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := headers[key]
		parts = append(parts, strconv.Itoa(len(key))+":"+key+strconv.Itoa(len(value))+":"+value)
	}
	return strings.Join(parts, ",")
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
