package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func auditPublicationKey(namespace string, identity ...string) string {
	parts := append([]string{namespace}, identity...)
	encoded, _ := json.Marshal(parts)
	digest := sha256.Sum256(encoded)
	return namespace + ":" + hex.EncodeToString(digest[:])
}
