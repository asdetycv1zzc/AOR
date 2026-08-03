package idempotency

import "testing"

func TestRequestDigestIsStableAcrossObjectOrder(t *testing.T) {
	first, err := RequestDigest([]byte(`{"type":"CREATE","body":{"b":2,"a":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := RequestDigest([]byte(`{"body":{"a":1,"b":2},"type":"CREATE"}`))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("digest mismatch: %s != %s", first, second)
	}
}

func TestScopeKeyBindsPrincipal(t *testing.T) {
	if ScopeKey("principal_a", "same") == ScopeKey("principal_b", "same") {
		t.Fatal("idempotency keys crossed principal scope")
	}
}
