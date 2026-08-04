package mcp

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeRejectsDuplicateMembersAndOversizedMessages(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"one","name":"two"}}`),
	} {
		if _, err := Decode(payload); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("Decode duplicate error = %v", err)
		}
	}
	oversized := make([]byte, MaxMessageBytes+1)
	if _, err := Decode(oversized); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Decode oversized error = %v", err)
	}
}

func TestInitializeParametersAcceptOptionalExtensions(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"experimental":{"x":true}},"clientInfo":{"name":"client","version":"1","icons":[{"src":"https://example.test/icon.png"}]},"optionalExtension":true}}`)
	message, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	var params InitializeParams
	if err := ParseParams(message, &params); err != nil || ValidateInitialize(params) != nil {
		t.Fatalf("initialize params=%#v err=%v", params, err)
	}
}

func TestJSONRPCBuildersPreserveStringAndNumericIDs(t *testing.T) {
	for _, id := range []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`"request-1"`)} {
		encoded, err := Request(id, "ping", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		message, err := Decode(encoded)
		if err != nil || !message.IsRequest() || string(message.ID) != string(id) {
			t.Fatalf("message=%#v err=%v", message, err)
		}
	}
}

func TestDecodeRejectsAmbiguousOrIncompleteResponses(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"failed"}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"failed"}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}`),
	} {
		if _, err := Decode(payload); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("Decode response error = %v", err)
		}
	}
	message, err := Decode([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":0,"message":"custom","data":"detail"}}`))
	if err != nil || message.Error == nil || message.Error.Code != 0 || message.Error.Data != "detail" {
		t.Fatalf("custom error = %#v err=%v", message.Error, err)
	}
}

func TestValidateInitializeRequiresCapabilities(t *testing.T) {
	params := InitializeParams{ProtocolVersion: BaselineProtocolVersion, ClientInfo: Implementation{Name: "client", Version: "1"}}
	if !errors.Is(ValidateInitialize(params), ErrInvalidMessage) {
		t.Fatal("initialize without capabilities was accepted")
	}
}
