package main

import "testing"

func TestAllowFallback(t *testing.T) {
	cases := []struct {
		policy, fallback string
		want             bool
	}{
		{"strict", "clue_only", false},
		{"strict", "confirm_only", false},
		{"strict", "none", false},
		{"strict", "", false},
		{"balanced", "clue_only", true},
		{"balanced", "confirm_only", true},
		{"balanced", "none", true}, // none 无回退，由上层分支判断
		{"", "clue_only", true},
	}
	for _, c := range cases {
		if got := allowFallback(c.policy, c.fallback); got != c.want {
			t.Errorf("allowFallback(%q,%q) = %v, want %v", c.policy, c.fallback, got, c.want)
		}
	}
}
