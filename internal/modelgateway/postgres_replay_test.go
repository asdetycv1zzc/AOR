package modelgateway

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestPostgresReplayCodecRequiresBoundedAES256Configuration(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x41}, 32)
	for _, config := range []ReplayStoreConfig{
		{KeyID: "key-v1", EncryptionKey: validKey, TTL: 30*24*time.Hour + time.Second},
		{KeyID: "key-v1", EncryptionKey: validKey[:31], TTL: time.Hour},
		{KeyID: "", EncryptionKey: validKey, TTL: time.Hour},
		{KeyID: "key\nv1", EncryptionKey: validKey, TTL: time.Hour},
	} {
		if _, err := newPostgresReplayCodec(config); err == nil {
			t.Fatalf("accepted replay config %#v", config)
		}
	}
	codec, err := newPostgresReplayCodec(ReplayStoreConfig{KeyID: "key-v1", EncryptionKey: validKey})
	if err != nil || codec.ttl != defaultModelReplayTTL {
		t.Fatalf("default codec = %#v, %v", codec, err)
	}
}

func TestPostgresReplayCiphertextIsBoundToTenantRequestAndDigest(t *testing.T) {
	codec, err := newPostgresReplayCodec(ReplayStoreConfig{
		KeyID: "key-v1", EncryptionKey: bytes.Repeat([]byte{0x52}, 32), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &PostgresBudgetLedger{clock: time.Now, replay: codec}
	replay := ModelReplay{
		InputSHA256: digestBytes([]byte("input")),
		Response: NormalizedResponse{
			RequestID: "request-1", Content: json.RawMessage(`{"ok":true}`),
			ModelVersion: "model-v1", Usage: Usage{InputTokens: 2, OutputTokens: 1, CostMicros: 3},
		},
	}
	nonce, ciphertext, err := ledger.encryptModelReplay("tenant-1", "request-1", replay)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, replay.Response.Content) {
		t.Fatal("ciphertext contains plaintext response")
	}
	additionalData := replayAdditionalData("tenant-1", "request-1", replay.InputSHA256, codec.keyID)
	plaintext, err := codec.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	var response NormalizedResponse
	if err := json.Unmarshal(plaintext, &response); err != nil || !sameNormalizedResponse(response, replay.Response) {
		t.Fatalf("decrypted response = %#v, %v", response, err)
	}
	for _, wrongAdditionalData := range [][]byte{
		replayAdditionalData("tenant-2", "request-1", replay.InputSHA256, codec.keyID),
		replayAdditionalData("tenant-1", "request-2", replay.InputSHA256, codec.keyID),
		replayAdditionalData("tenant-1", "request-1", digestBytes([]byte("different")), codec.keyID),
	} {
		if _, err := codec.aead.Open(nil, nonce, ciphertext, wrongAdditionalData); err == nil {
			t.Fatal("ciphertext opened with mismatched identity")
		}
	}
}
