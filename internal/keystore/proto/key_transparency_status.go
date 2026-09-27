package proto

type KeyTransparencyStatusRequest struct{}

func (KeyTransparencyStatusRequest) Validate() error { return nil }

// KeyTransparencyTrustErrorInvalid is reported when a trust file is
// configured but unusable, so key changes are being refused.
const KeyTransparencyTrustErrorInvalid = "invalid"

type KeyTransparencyStatusResponse struct {
	Configured bool   `json:"configured"`
	TrustError string `json:"trust_error,omitempty"`
	Anchored   bool   `json:"anchored"`
	Origin     string `json:"origin,omitempty"`
	TreeSize   uint64 `json:"tree_size,omitempty"`
	RootHash   string `json:"root_hash,omitempty"`
}
