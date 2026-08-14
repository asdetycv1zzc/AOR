package mockenv

import "testing"

func TestEnabledValue(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "true", want: true},
		{value: " YES ", want: true},
		{value: "1", want: true},
		{value: "off", want: false},
		{value: "", want: false},
	} {
		if got := enabledValue(test.value); got != test.want {
			t.Fatalf("enabledValue(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}
