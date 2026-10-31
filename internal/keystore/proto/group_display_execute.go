package proto

const CurrentGroupDisplayExecuteMaxRequestBytes = 20 * 1024

// CurrentGroupDisplayExecuteRequest repeats the exact prepared operation.
// Keeper compares it with the signed decision before any protected operation.
type CurrentGroupDisplayExecuteRequest struct {
	Prepare  CurrentGroupDisplayPrepareRequest `json:"prepare"`
	Decision CurrentGroupDisplayDecision       `json:"decision"`
}

func (r CurrentGroupDisplayExecuteRequest) Validate() error {
	if err := r.Prepare.Validate(); err != nil {
		return err
	}
	return r.Decision.Validate()
}

type CurrentGroupDisplayExecuteResponseData struct {
	Challenge              string `json:"challenge"`
	OperationDigest        string `json:"operation_digest"`
	KeeperPublicKeySPKIB64 string `json:"keeper_public_key_spki_b64"`
	IVB64                  string `json:"iv_b64"`
	CiphertextB64          string `json:"ciphertext_b64"`
}
