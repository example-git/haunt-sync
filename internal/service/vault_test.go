package service

import (
	"strings"
	"testing"
)

func TestArchiveVaultScopes(t *testing.T) {
	one := "server:" + strings.Repeat("a", 43)
	two := "server:" + strings.Repeat("b", 43)
	for _, test := range []struct {
		device, name string
		allowed      bool
	}{
		{"full", "archive:full", true},
		{"full", "archive-chunk:full:" + strings.Repeat("c", 43), true},
		{one, "archive-chunk:" + one + ":" + strings.Repeat("c", 43), true},
		{one, "archive-chunk:" + two + ":" + strings.Repeat("c", 43), false},
		{one, "archive-chunk:full:" + strings.Repeat("c", 43), false},
		{"email", "archive-chunk:full:" + strings.Repeat("c", 43), false},
		{"full", "archive-chunk:full:short", false},
		{"full", "archive-chunk:archive:full:" + strings.Repeat("c", 43), false},
		{"full", "archive:" + one, true},
		{one, "archive:" + one, true},
		{one, "archive:full", false},
		{one, "archive:" + two, false},
		{"email", "archive:full", false},
		{"full", "archive:archive:full", false},
		{"full", "archive:server:short", false},
		{"full", "archive:", false},
		{"full", "full", true},
		{one, one, true},
		{one, two, false},
	} {
		t.Run(test.device+"/"+test.name, func(t *testing.T) {
			err := vaultScope(Device{Scope: test.device}, test.name)
			if (err == nil) != test.allowed {
				t.Fatalf("scope acceptance=%v, expected=%v", err == nil, test.allowed)
			}
		})
	}
}
