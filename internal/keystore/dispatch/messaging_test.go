// messaging_test.go — unit tests for dispatch.Messenger.
//
// **Defects this test catches:**
//   - regressions in length-prefixed framing across EOF / zero-length /
//     oversized / truncated branches
//   - SendResponse failing to write 4-byte little-endian length + JSON body
//     in the correct order
//   - Read/Write roundtrip consistency regressions
//
// **Previous location:** internal/keystore/messaging_test.go.
package dispatch

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestMessenger_ReadMessage_Valid(t *testing.T) {
	body := []byte(`{"action":"ping"}`)
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(len(body)))
	buf.Write(body)

	m := NewMessenger(buf, nil, nil)
	msg, err := m.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if string(msg) != string(body) {
		t.Errorf("msg = %q, want %q", string(msg), string(body))
	}
}

func TestMessenger_ReadMessage_EOF(t *testing.T) {
	m := NewMessenger(bytes.NewReader(nil), nil, nil)
	_, err := m.ReadMessage()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestMessenger_ReadMessage_ZeroLength(t *testing.T) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(0))

	m := NewMessenger(buf, nil, nil)
	_, err := m.ReadMessage()
	if err == nil {
		t.Error("expected error for zero-length message")
	}
}

func TestMessenger_ReadMessage_OversizedMessage(t *testing.T) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, MaxMessageSize+1)

	m := NewMessenger(buf, nil, nil)
	_, err := m.ReadMessage()
	if err == nil {
		t.Error("expected error for oversized message")
	}
}

func TestMessenger_ReadMessage_TruncatedBody(t *testing.T) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(100)) // says 100 bytes
	buf.Write([]byte("short"))                          // only 5 bytes

	m := NewMessenger(buf, nil, nil)
	_, err := m.ReadMessage()
	if err == nil {
		t.Error("expected error for truncated body")
	}
}

func TestMessenger_SendResponse(t *testing.T) {
	out := &bytes.Buffer{}
	m := NewMessenger(nil, out, nil)

	resp := proto.BaseResponse{Success: true, Data: proto.PingResponseData{Version: "0.0.6"}}
	err := m.SendResponse(resp)
	if err != nil {
		t.Fatalf("SendResponse() error = %v", err)
	}

	// Read back: 4-byte length + JSON body
	raw := out.Bytes()
	if len(raw) < 4 {
		t.Fatal("output too short")
	}

	length := binary.LittleEndian.Uint32(raw[:4])
	body := raw[4:]
	if uint32(len(body)) != length {
		t.Errorf("length header = %d, body size = %d", length, len(body))
	}

	var got proto.BaseResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal response error = %v", err)
	}
	if !got.Success {
		t.Error("expected success = true")
	}
}

func TestMessenger_ReadWrite_Roundtrip(t *testing.T) {
	pipe := &bytes.Buffer{}

	// Write
	writer := NewMessenger(nil, pipe, nil)
	resp := proto.BaseResponse{Success: true, Data: "hello"}
	writer.SendResponse(resp)

	// Read back
	reader := NewMessenger(pipe, nil, nil)
	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	var got proto.BaseResponse
	json.Unmarshal(msg, &got)
	if !got.Success {
		t.Error("roundtrip: expected success = true")
	}
}
