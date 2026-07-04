package dispatch

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// MaxMessageSize defines the maximum allowed message size (10MB)
// This prevents memory exhaustion attacks from malicious extensions
const MaxMessageSize uint32 = 10 * 1024 * 1024 // 10MB

// Messenger is the Native Messaging length-prefixed framing transport.
// Logger is passed as an explicit argument, removing DefaultApp() dependency.
type Messenger struct {
	in  io.Reader
	out io.Writer
	log logger.Logger
}

// NewMessenger constructs a length-prefixed framing messenger. log is used for
// response-masking logging (logSafeResponse); if nil, the caller of
// NewMessenger is responsible. Production callers inject App.Logger explicitly
// via app.NewMessenger (aliases.go).
func NewMessenger(in io.Reader, out io.Writer, log logger.Logger) *Messenger {
	return &Messenger{
		in:  in,
		out: out,
		log: log,
	}
}

// ReadMessage reads a length-prefixed message from the input
func (m *Messenger) ReadMessage() ([]byte, error) {
	var length uint32

	if err := binary.Read(m.in, binary.LittleEndian, &length); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read message length: %v", err)
	}

	if length > MaxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds maximum allowed size %d", length, MaxMessageSize)
	}

	if length == 0 {
		return nil, fmt.Errorf("invalid message: zero length")
	}

	msgBody := make([]byte, length)
	if _, err := io.ReadFull(m.in, msgBody); err != nil {
		return nil, fmt.Errorf("failed to read message body: %v", err)
	}

	return msgBody, nil
}

// SendResponse writes a JSON-serialized response with a 4-byte little-endian length prefix.
func (m *Messenger) SendResponse(resp proto.BaseResponse) error {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("response serialization error: %v", err)
	}

	m.logSafeResponse(resp)

	// Write response length
	if err := binary.Write(m.out, binary.LittleEndian, uint32(len(respBytes))); err != nil {
		return fmt.Errorf("failed to write response length: %w", err)
	}

	// Write body
	if _, err := m.out.Write(respBytes); err != nil {
		return fmt.Errorf("failed to write response body: %w", err)
	}

	return nil
}

// logSafeResponse emits a masked form of the response to the diagnostic log.
// The Data field may contain sensitive payloads, so it is replaced with
// "[DATA_MASKED]"; only Success/Error/ErrorCode are kept as-is.
//
// Uses Messenger.log instead of DefaultApp().Logger so tests can capture via
// NewMessenger(_, _, MemoryLogger{}). If Messenger.log is nil, logging is
// skipped (defensive).
func (m *Messenger) logSafeResponse(resp proto.BaseResponse) {
	if m.log == nil {
		return
	}
	safeResp := proto.BaseResponse{
		Success:   resp.Success,
		Error:     resp.Error,
		ErrorCode: resp.ErrorCode,
		Data:      "[DATA_MASKED]",
	}

	if resp.Data == nil {
		safeResp.Data = nil
	}

	safeBytes, _ := json.Marshal(safeResp)
	m.log.Printf("sending response: %s", string(safeBytes))
}
