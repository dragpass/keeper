package proto

type KeyTransparencyEvidence struct {
	StatementB64        string   `json:"statement_b64"`
	SaltB64             string   `json:"salt_b64"`
	CheckpointB64       string   `json:"checkpoint_b64"`
	LeafIndex           uint64   `json:"leaf_index"`
	InclusionProofB64   []string `json:"inclusion_proof_b64"`
	PreviousTreeSize    uint64   `json:"previous_tree_size"`
	ConsistencyProofB64 []string `json:"consistency_proof_b64"`
}
