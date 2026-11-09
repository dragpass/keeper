package localrpc

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Each split and proof action has a paired App route whose strict decode
// carries every field of the action's request, including its signed
// decision or receipt, to the handler unchanged.
func TestArchiveSplitRoutesForwardTheWholeRequest(t *testing.T) {
	split := proto.ArchiveKeySplitRequest{
		OperationID: routeOwner, AccountID: routeOwner, OrgID: routePeer, ThresholdN: 2,
		RecipientPublicKeys: []string{"a", "b"}, RecipientAccountIDs: []string{routeOwner, routePeer},
		ConfigDigest: "c", Decision: &proto.ArchiveSplitDecision{Challenge: "x", Recipients: []proto.ArchiveSplitRecipient{{AccountID: routePeer, KeyFingerprint: "f"}}, SessionIssuedAtNanos: 9, Signature: "s"},
	}
	proof := proto.ArchiveShareOpenProofRequest{
		AccountID: routeOwner, OrgID: routePeer, OperationID: routeOwner, ConfigDigest: "c", ShareIndex: 2,
		WrappedKey: "w", Ciphertext: "t", ProofPublicKey: "p",
		Decision: &proto.ArchiveShareOpenProofDecision{Challenge: "x", PersonID: routePeer, ServerNonce: "n", SessionIssuedAtNanos: 9, Signature: "s"},
	}
	cases := []struct {
		path    string
		action  string
		request any
	}{
		{"/v1/archive/archive_split_prepare", proto.ActionArchiveSplitPrepare, &proto.ArchiveSplitPrepareRequest{Request: split, TokenID: routeOwner, SessionIssuedAtNanos: 7}},
		{"/v1/archive/archive_key_split", proto.ActionArchiveKeySplit, &split},
		{"/v1/archive/archive_share_proof_prepare", proto.ActionArchiveShareProofPrepare, &proto.ArchiveShareProofPrepareRequest{Request: proof, TokenID: routeOwner, SessionIssuedAtNanos: 7}},
		{"/v1/archive/archive_share_open_proof", proto.ActionArchiveShareOpenProof, &proof},
		{"/v1/archive/archive_split_status", proto.ActionArchiveSplitStatus, &proto.ArchiveSplitStatusRequest{OrgID: routePeer}},
		{"/v1/archive/archive_split_finalize", proto.ActionArchiveSplitFinalize, &proto.ArchiveSplitFinalizeRequest{OrgID: routePeer, Receipt: &proto.ArchiveSplitFinalizationReceipt{OperationID: routeOwner, OrgID: routePeer, SharesDigest: "d", FinalizedAt: 5, ServerKeyVersion: 1, Signature: "s"}}},
		{"/v1/archive/archive_split_abandon", proto.ActionArchiveSplitAbandon, &proto.ArchiveSplitAbandonRequest{OrgID: routePeer, Receipt: &proto.ArchiveSplitClosureReceipt{OperationID: routeOwner, OrgID: routePeer, Status: "cancelled", ServerKeyVersion: 1, Signature: "s"}}},
	}
	for _, c := range cases {
		route, found := appRoutes[c.path]
		if !found || route.action != c.action || route.input == nil || route.run != nil || route.shape != nil {
			t.Fatalf("%s must be a plain paired App route for %s", c.path, c.action)
		}
		body, err := json.Marshal(c.request)
		if err != nil {
			t.Fatal(err)
		}
		input := route.input()
		if err := decodeStrict(bytes.NewReader(body), input); err != nil {
			t.Fatalf("%s refused its own request: %v", c.path, err)
		}
		payload := any(input)
		if route.bind != nil {
			if payload, err = route.bind(nil, input); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(payload, c.request) {
			t.Fatalf("%s did not forward the request unchanged", c.path)
		}
	}
}
