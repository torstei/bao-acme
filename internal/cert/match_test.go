// SPDX-License-Identifier: MPL-2.0

package cert

import "testing"

func TestCovers(t *testing.T) {
	names := []string{"*.example.com", "example.org", "192.0.2.1", "2001:db8::1"}
	cases := map[string]bool{
		"a.example.com":   true,
		"A.Example.COM.":  true,
		"example.com":     false,
		"a.b.example.com": false,
		".example.com":    false,
		"example.org":     true,
		"www.example.org": false,
		"192.0.2.1":       true,
		"192.0.2.2":       false,
		"2001:db8:0::1":   true,
		"":                false,
		"*.example.com":   true,
		"xexample.com":    false,
	}
	for host, want := range cases {
		if got := Covers(names, host); got != want {
			t.Errorf("Covers(%q) = %v, want %v", host, got, want)
		}
	}
}
