package idempotency

import "github.com/akimisaka/aor/pkg/canonicaljson"

func RequestDigest(commandJSON []byte) (string, error) {
	return canonicaljson.Digest(commandJSON)
}

func ScopeKey(principalID, idempotencyKey string) string {
	return principalID + "\x00" + idempotencyKey
}
