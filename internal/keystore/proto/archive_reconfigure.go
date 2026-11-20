// archive_reconfigure.go — payloads for the legacy quorum reconfiguration
// actions (lv90).

package proto

// ArchiveReconfigureStageRequest stages a new archive key for the org's
// reconfiguration operation. Both IDs are required: the org selects the slot
// and the operation ID binds the journal.
type ArchiveReconfigureStageRequest struct {
	OrgID       string `json:"org_id"`
	OperationID string `json:"operation_id"`
}

func (r ArchiveReconfigureStageRequest) Validate() error {
	if err := requireMessageUUID(r.OrgID, "org_id"); err != nil {
		return err
	}
	return requireMessageUUID(r.OperationID, "operation_id")
}

// ArchiveReconfigureStageResponseData carries only public material.
type ArchiveReconfigureStageResponseData struct {
	PublicKey   string `json:"publickey"`
	Fingerprint string `json:"fingerprint"` // hex(sha256(public key PEM))
}
