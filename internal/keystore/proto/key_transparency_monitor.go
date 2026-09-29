package proto

import (
	"encoding/base64"
	"errors"
)

const (
	KeyTransparencyMonitorMaxEvents      = 100
	KeyTransparencyMonitorMaxRequestSize = 8 * 1024 * 1024
	keyTransparencyMonitorMaxFieldSize   = 96 * 1024
)

type KeyTransparencyMonitorEventRequest struct {
	EventID    string                  `json:"event_id"`
	SourceType string                  `json:"source_type"`
	Evidence   KeyTransparencyEvidence `json:"evidence"`
}

type KeyTransparencyMonitorRequest struct {
	AccountID string                               `json:"account_id"`
	Events    []KeyTransparencyMonitorEventRequest `json:"events"`
}

func (r KeyTransparencyMonitorRequest) Validate() error {
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if len(r.Events) == 0 || len(r.Events) > KeyTransparencyMonitorMaxEvents {
		return errors.New("events must contain between 1 and 100 entries")
	}
	seen := make(map[string]struct{}, len(r.Events))
	for _, event := range r.Events {
		if err := requireMessageUUID(event.EventID, "events.event_id"); err != nil {
			return err
		}
		if _, duplicate := seen[event.EventID]; duplicate {
			return errors.New("events contain a duplicate event_id")
		}
		seen[event.EventID] = struct{}{}
		if event.SourceType != "account_key_enrollment" && event.SourceType != "account_key_rotation" && event.SourceType != "mls_leaf_binding" {
			return errors.New("events contain an unsupported source_type")
		}
		if len(event.Evidence.StatementB64) > keyTransparencyMonitorMaxFieldSize || len(event.Evidence.CheckpointB64) > keyTransparencyMonitorMaxFieldSize || len(event.Evidence.SaltB64) > 128 || len(event.Evidence.InclusionProofB64) > 64 || len(event.Evidence.ConsistencyProofB64) > 64 {
			return errors.New("events contain oversized evidence")
		}
		if _, err := base64.StdEncoding.DecodeString(event.Evidence.StatementB64); err != nil {
			return errors.New("events contain malformed statement evidence")
		}
		for _, nodes := range [][]string{event.Evidence.InclusionProofB64, event.Evidence.ConsistencyProofB64} {
			for _, node := range nodes {
				if len(node) > 128 {
					return errors.New("events contain oversized proof nodes")
				}
			}
		}
	}
	return nil
}

type KeyTransparencyMonitorEventResult struct {
	EventID           string `json:"event_id"`
	SourceType        string `json:"source_type"`
	DeviceID          string `json:"device_id,omitempty"`
	Fingerprint       string `json:"fingerprint"`
	Reason            string `json:"reason"`
	KnownOnThisDevice bool   `json:"known_on_this_device"`
}

type KeyTransparencyMonitorResponse struct {
	AccountID      string                              `json:"account_id"`
	Checked        int                                 `json:"checked"`
	CheckpointSize uint64                              `json:"checkpoint_size"`
	Events         []KeyTransparencyMonitorEventResult `json:"events"`
}
