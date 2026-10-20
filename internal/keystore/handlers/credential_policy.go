package handlers

import (
	"crypto/sha256"
	"encoding/hex"
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

// credentialPolicyCanonicalPrefix opens every version 2 canonical. A version 1
// canonical starts with an entry UUID, so no signature over one can verify as
// the other.
const credentialPolicyCanonicalPrefix = "dragpass.credential-policy|2|"

// canonicalCredentialPolicy is the version 2 signing input:
//
//	dragpass.credential-policy|2|<len>:<execution_nonce>|<len>:<target_query>|<len>:<body_sha256>|<body>
//
// The three binding fields sit at fixed positions and are length-prefixed, so
// a query or nonce containing "|" cannot move a boundary. <body> is the field
// list every earlier format signed (canonicalCredentialPolicyBody). ariadne's
// canonicalPolicyString builds the same bytes; both repositories assert the
// same literal for a shared fixture.
func canonicalCredentialPolicy(p proto.CredentialPolicy) string {
	return credentialPolicyCanonicalPrefix +
		canonicalCredentialLengthPrefixed(p.ExecutionNonce) + "|" +
		canonicalCredentialLengthPrefixed(p.TargetQuery) + "|" +
		canonicalCredentialLengthPrefixed(p.BodySHA256) + "|" +
		canonicalCredentialPolicyBody(p)
}

// canonicalCredentialPolicyBody is the target, template and command part of
// the canonical.
func canonicalCredentialPolicyBody(p proto.CredentialPolicy) string {
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
	// Both trailing blocks are appended only when their template is non-empty.
	// The slots are unambiguous: expiry is
	// RFC3339 (validated by time.Parse before this is called) and cannot contain
	// "|", every part of both blocks is length-prefixed and self-delimiting, and
	// a policy injects into exactly one place, so query and exec are never both
	// present.
	if len(p.QueryTemplate) > 0 {
		parts = append(parts, canonicalCredentialHeaders(p.QueryTemplate))
	}
	if len(p.EnvTemplate) > 0 {
		// The executable and cwd are length-prefixed like everything else in this
		// block. A POSIX path may legally contain "|", and without the prefix a
		// crafted path could absorb the following separator and make two distinct
		// commands canonicalize to the same bytes.
		parts = append(parts,
			canonicalCredentialLengthPrefixed(p.ExecExecutable),
			canonicalCredentialArgv(p.ExecArgv),
			canonicalCredentialLengthPrefixed(p.ExecCwd),
			canonicalCredentialHeaders(p.EnvTemplate),
		)
	}
	return strings.Join(parts, "|")
}

// canonicalCredentialLengthPrefixed encodes one value as "<byte length>:<value>",
// the same shape every other length-prefixed field in the canonical uses.
func canonicalCredentialLengthPrefixed(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
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
		parts = append(parts, canonicalCredentialLengthPrefixed(arg))
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
	// Only version 2 binds the execution nonce, the query and the body. A policy
	// in any other format is refused here, before its signature is checked, so
	// there is no path on which an older format is accepted instead.
	if p.PolicyVersion != proto.CredentialPolicyVersion {
		return false, errs.CodeResponse(errs.ErrCodeValidation,
			"credential policy version is not supported; only policy_version 2 is accepted")
	}
	if len(p.ExecutionNonce) != proto.CredentialExecutionNonceChars {
		return false, errs.CodeResponse(errs.ErrCodeValidation,
			"policy.execution_nonce must be "+strconv.Itoa(proto.CredentialExecutionNonceChars)+" Base64URL characters")
	}
	if !isCredentialBodyDigest(p.BodySHA256) {
		return false, errs.CodeResponse(errs.ErrCodeValidation,
			"policy.body_sha256 must be empty or 64 lowercase hex characters")
	}
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

// isCredentialBodyDigest accepts "" (no body) or a lowercase hex SHA-256.
func isCredentialBodyDigest(digest string) bool {
	if digest == "" {
		return true
	}
	if len(digest) != 64 {
		return false
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// credentialBodyDigest is the lowercase hex SHA-256 of the exact bytes the
// request will carry, or "" when it carries none. The server signs the same
// value over the bytes it received.
func credentialBodyDigest(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// requestQueryMatchesPolicy checks that target_url carries exactly the signed
// query, and in a form whose bytes are the bytes written on the request line:
// no fragment, no empty "?", and only printable ASCII. The comparison is byte
// for byte, so parameter order, duplicates and percent-encoding are all bound.
func requestQueryMatchesPolicy(targetURL string, p proto.CredentialPolicy) error {
	if strings.Contains(targetURL, "#") {
		return fmt.Errorf("target_url must not carry a fragment")
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target_url")
	}
	if u.ForceQuery && u.RawQuery == "" {
		return fmt.Errorf("target_url must not end with an empty query")
	}
	for i := 0; i < len(u.RawQuery); i++ {
		if c := u.RawQuery[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("target_url query must be percent-encoded printable ASCII")
		}
	}
	if u.RawQuery != p.TargetQuery {
		return fmt.Errorf("request query does not match signed target_query")
	}
	return nil
}
