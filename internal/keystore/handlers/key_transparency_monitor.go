package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func HandleKeyTransparencyMonitor(d Deps, request proto.KeyTransparencyMonitorRequest) proto.BaseResponse {
	if err := request.Validate(); err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "key transparency monitor request is invalid")
	}
	trust, err := usableTrust(d)
	if err != nil {
		return keyTransparencyRefusal(d, err)
	}
	if trust == nil {
		return keyTransparencyRefusal(d, keytransparency.ErrInvalidCheckpoint)
	}
	response := proto.KeyTransparencyMonitorResponse{
		AccountID: request.AccountID,
		Events:    make([]proto.KeyTransparencyMonitorEventResult, 0, len(request.Events)),
	}
	for _, event := range request.Events {
		statement, err := base64.StdEncoding.DecodeString(event.Evidence.StatementB64)
		if err != nil {
			return keyTransparencyRefusal(d, keytransparency.ErrInvalidCheckpoint)
		}
		verified, err := keytransparency.VerifyAccountStatement(statement, request.AccountID)
		if err != nil || verified.SourceType != event.SourceType {
			return keyTransparencyRefusal(d, keytransparency.ErrInvalidCheckpoint)
		}
		checkpoint, err := keytransparency.VerifyAndPersistEvidence(d.Store, *trust, event.Evidence, statement)
		if err != nil {
			return keyTransparencyRefusal(d, err)
		}
		known, err := keychain.HasKnownKeyTransparencyEvent(d.Store, request.AccountID, statement)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "key transparency event state is unavailable")
		}
		if !known && verified.SourceType == keytransparency.StatementAccountKeyEnrollment {
			known = isOwnActiveKey(d, verified.Fingerprint)
		}
		response.Events = append(response.Events, proto.KeyTransparencyMonitorEventResult{
			EventID: event.EventID, SourceType: verified.SourceType, DeviceID: verified.DeviceID,
			Fingerprint: verified.Fingerprint, Reason: verified.Reason, KnownOnThisDevice: known,
		})
		response.Checked++
		response.CheckpointSize = checkpoint.Checkpoint.Size
	}
	return proto.BaseResponse{Success: true, Data: response}
}

// isOwnActiveKey reports whether fingerprint is the account key this Keeper
// holds. An enrollment of that key is this device's own signup: the statement
// was verified to carry that key's signature, which only a holder of the
// private key can make, and signup stages no statement for the digest record.
func isOwnActiveKey(d Deps, fingerprint string) bool {
	own, err := keychain.GetPublicKey(d.Store)
	if err != nil || own == "" {
		return false
	}
	return crypto.AccountKeyFingerprint([]byte(own)) == fingerprint
}
