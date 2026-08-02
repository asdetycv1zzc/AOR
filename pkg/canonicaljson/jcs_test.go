package canonicaljson

import (
	"testing"
)

func TestCanonicalizeSortsObjectMembers(t *testing.T) {
	got, err := Canonicalize([]byte(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("canonical = %s", got)
	}
}

func TestDigestChangesWithImmutableContent(t *testing.T) {
	first, err := Digest([]byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest([]byte(`{"a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different content must not share a digest")
	}
}

func TestCanonicalizeRejectsDuplicateObjectMember(t *testing.T) {
	if _, err := Canonicalize([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate keys must be rejected")
	}
}

func TestDigestObjectWithoutFieldsExcludesOnlyEnvelopeFields(t *testing.T) {
	first, err := DigestObjectWithoutFields([]byte(`{"content":{"id":1},"status":"DRAFT","extra":{"v":2}}`), "status")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DigestObjectWithoutFields([]byte(`{"extra":{"v":2},"status":"APPROVED","content":{"id":1}}`), "status")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("mutable envelope field changed digest: %s != %s", first, second)
	}
	third, err := DigestObjectWithoutFields([]byte(`{"content":{"id":1},"status":"DRAFT","extra":{"v":3}}`), "status")
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("unknown content fields must remain digest-bound")
	}
}
