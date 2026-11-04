package proto

import (
	"crypto/sha256"
	"encoding/json"
)

// GroupRewrapMemberRequestDigest commits to every field that can affect the
// source unwrap, pin decision, or output wrap. Signed decision fields are
// intentionally absent, so the request can be prepared before API issuance.
func GroupRewrapMemberRequestDigest(req DEKRewrapForMemberRequest) ([32]byte, error) {
	canonical, err := json.Marshal(struct {
		Domain             string                   `json:"domain"`
		WrappedForMeB64    string                   `json:"wrapped_for_me_b64"`
		OtherPublicKey     string                   `json:"other_public_key"`
		OwnerAccountID     string                   `json:"owner_account_id"`
		OtherAccountID     string                   `json:"other_account_id"`
		RotationStatements []KeyRotationStatement   `json:"rotation_statements"`
		EnrollmentEvidence *KeyTransparencyEvidence `json:"enrollment_evidence"`
		GrantContext       *GrantContext            `json:"grant_context"`
	}{
		Domain:             "dragpass:group-rewrap-member-request:v1",
		WrappedForMeB64:    req.WrappedForMeB64,
		OtherPublicKey:     req.OtherPublicKey,
		OwnerAccountID:     req.OwnerAccountID,
		OtherAccountID:     req.OtherAccountID,
		RotationStatements: req.RotationStatements,
		EnrollmentEvidence: req.EnrollmentEvidence,
		GrantContext:       req.GrantContext,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// GroupRewrapManyRequestDigest also binds later recipients and the output
// policy switch before the first recipient pin can be changed.
func GroupRewrapManyRequestDigest(req DEKUnwrapAndRewrapForManyRequest) ([32]byte, error) {
	canonical, err := json.Marshal(struct {
		Domain              string               `json:"domain"`
		WrappedForMeB64     string               `json:"wrapped_for_me_b64"`
		Recipients          []DEKRewrapRecipient `json:"recipients"`
		OwnerAccountID      string               `json:"owner_account_id"`
		GrantContext        *GrantContext        `json:"grant_context"`
		NarrowToDecryptOnly bool                 `json:"narrow_to_decrypt_only"`
	}{
		Domain:              "dragpass:group-rewrap-many-request:v1",
		WrappedForMeB64:     req.WrappedForMeB64,
		Recipients:          req.Recipients,
		OwnerAccountID:      req.OwnerAccountID,
		GrantContext:        req.GrantContext,
		NarrowToDecryptOnly: req.NarrowToDecryptOnly,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
