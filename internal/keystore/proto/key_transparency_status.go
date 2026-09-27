package proto

type KeyTransparencyStatusRequest struct{}

func (KeyTransparencyStatusRequest) Validate() error { return nil }

type KeyTransparencyStatusResponse struct {
	Configured bool   `json:"configured"`
	Anchored   bool   `json:"anchored"`
	Origin     string `json:"origin,omitempty"`
	TreeSize   uint64 `json:"tree_size,omitempty"`
	RootHash   string `json:"root_hash,omitempty"`
}
