package dispatch

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type MockRequestWithValidator struct {
	Field string `json:"field" validate:"required"`
}

func (m *MockRequestWithValidator) Validate() error {
	if m.Field == "fail" {
		return errors.New("validation failed by mock")
	}
	return nil
}

func TestProcess(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "Success: Valid JSON and Validation passes",
			payload:     `{"field": "success"}`,
			shouldError: false,
		},
		{
			name:        "Failure: Invalid JSON format",
			payload:     `{"field": "broken...`,
			shouldError: true,
			errorMsg:    "invalid payload format",
		},
		{
			name:        "Failure: Validation fails",
			payload:     `{"field": "fail"}`,
			shouldError: true,
			errorMsg:    "validation failed by mock",
		},
		{
			name:        "Success: Empty payload (should proceed)",
			payload:     ``,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHandler := func(req MockRequestWithValidator) proto.BaseResponse {
				return proto.BaseResponse{Success: true}
			}

			resp := process(json.RawMessage(tt.payload), mockHandler)

			// verify result
			if tt.shouldError {
				if resp.Success {
					t.Errorf("Expected error but got success")
				}
				if resp.Error != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, resp.Error)
				}
				if resp.ErrorCode != string(errs.ErrCodeValidation) {
					t.Errorf("Expected validation error code, got %q", resp.ErrorCode)
				}
			} else {
				if !resp.Success {
					t.Errorf("Expected success but got error: %s", resp.Error)
				}
			}
		})
	}
}

type MockRequestNonValidator struct {
	Field string `json:"field"`
}

func TestProcess_NoValidator(t *testing.T) {
	payload := json.RawMessage(`{"field": "anything"}`)

	mockHandler := func(req MockRequestNonValidator) proto.BaseResponse {
		if req.Field != "anything" {
			return proto.BaseResponse{Success: false, Error: "data mismatch"}
		}
		return proto.BaseResponse{Success: true}
	}

	resp := process(payload, mockHandler)

	if !resp.Success {
		t.Errorf("Expected success for struct without Validator, but got error: %s", resp.Error)
	}
}
