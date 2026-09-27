package keytransparency

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

const TrustConfigEnv = "DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE"

type trustConfig struct {
	Origin                  string   `json:"origin"`
	LogVerifier             string   `json:"log_verifier"`
	WitnessVerifiers        []string `json:"witness_verifiers"`
	Quorum                  int      `json:"quorum"`
	MaxCheckpointAgeSeconds int64    `json:"max_checkpoint_age_seconds"`
	FutureSkewSeconds       int64    `json:"future_skew_seconds"`
}

// Gate is what the Keeper enforces for account-key rotations and entering MLS
// leaves. No trust file keeps the pre-transparency TOFU and pin rules. A trust
// file that is present but unusable must not quietly fall back to those rules:
// an attacker who can corrupt or delete the file's contents would otherwise
// turn verification off, so ConfigErr keeps every key change refused.
type Gate struct {
	Trust     *Trust
	ConfigErr error
}

func (g Gate) Required() bool { return g.Trust != nil || g.ConfigErr != nil }

func LoadGateFromEnv() Gate {
	path := strings.TrimSpace(os.Getenv(TrustConfigEnv))
	if path == "" {
		return Gate{}
	}
	trust, err := loadTrustFile(path)
	if err != nil {
		return Gate{ConfigErr: fmt.Errorf("%w: %v", ErrTrustInvalid, err)}
	}
	return Gate{Trust: trust}
}

func loadTrustFile(path string) (*Trust, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key transparency trust file: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var config trustConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode key transparency trust file: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("key transparency trust file must contain one JSON value")
	}
	if strings.TrimSpace(config.Origin) == "" || config.Quorum != 2 || len(config.WitnessVerifiers) != 3 ||
		config.MaxCheckpointAgeSeconds <= 0 || config.FutureSkewSeconds < 0 {
		return nil, errors.New("key transparency trust file must configure origin, three witnesses, 2-of-3 quorum, and freshness")
	}
	logVerifier, err := note.NewVerifier(strings.TrimSpace(config.LogVerifier))
	if err != nil {
		return nil, fmt.Errorf("parse key transparency log verifier: %w", err)
	}
	witnessVerifiers := make([]note.Verifier, 0, len(config.WitnessVerifiers))
	names := map[string]struct{}{logVerifier.Name(): {}}
	for _, encoded := range config.WitnessVerifiers {
		verifier, err := formatnote.NewVerifierForCosignatureV1(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("parse key transparency witness verifier: %w", err)
		}
		if _, exists := names[verifier.Name()]; exists || verifier.Name() == "" {
			return nil, errors.New("key transparency verifier names must be distinct and non-empty")
		}
		names[verifier.Name()] = struct{}{}
		witnessVerifiers = append(witnessVerifiers, verifier)
	}
	return &Trust{
		Origin: config.Origin, LogVerifier: logVerifier, WitnessVerifiers: witnessVerifiers,
		Quorum: 2, MaxCheckpointAge: time.Duration(config.MaxCheckpointAgeSeconds) * time.Second,
		FutureSkew: time.Duration(config.FutureSkewSeconds) * time.Second,
	}, nil
}
