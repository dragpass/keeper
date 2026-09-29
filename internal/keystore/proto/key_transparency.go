package proto

import (
	"encoding/base64"
)

type KeyTransparencyEvidence struct {
	StatementB64        string   `json:"statement_b64"`
	SaltB64             string   `json:"salt_b64"`
	CheckpointB64       string   `json:"checkpoint_b64"`
	LeafIndex           uint64   `json:"leaf_index"`
	InclusionProofB64   []string `json:"inclusion_proof_b64"`
	PreviousTreeSize    uint64   `json:"previous_tree_size"`
	ConsistencyProofB64 []string `json:"consistency_proof_b64"`
}

func validateKeyTransparencyEvidence(evidence *KeyTransparencyEvidence, field string) error {
	if evidence == nil {
		return nil
	}
	if len(evidence.StatementB64) == 0 || len(evidence.StatementB64) > 90*1024 ||
		len(evidence.SaltB64) > 128 || len(evidence.CheckpointB64) > 90*1024 ||
		len(evidence.InclusionProofB64) > 64 || len(evidence.ConsistencyProofB64) > 64 {
		return newValidationError(field, "proof exceeds the size limit")
	}
	if _, err := base64.StdEncoding.DecodeString(evidence.StatementB64); err != nil {
		return newValidationError(field, "statement is malformed")
	}
	for _, nodes := range [][]string{evidence.InclusionProofB64, evidence.ConsistencyProofB64} {
		for _, node := range nodes {
			if len(node) > 128 {
				return newValidationError(field, "proof node exceeds the size limit")
			}
		}
	}
	return nil
}
