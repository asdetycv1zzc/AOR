package globalaudit

import "testing"

func TestNewFollowupUUIDReturnsDistinctUUIDv7Values(t *testing.T) {
	first, err := newFollowupUUID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFollowupUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !uuidV7(first) || !uuidV7(second) || first == second {
		t.Fatalf("follow-up IDs = %q, %q", first, second)
	}
}
