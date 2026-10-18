// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"strings"
	"testing"
)

func TestNormaliseNames(t *testing.T) {
	got, err := NormaliseNames([]string{"WWW.Example.COM.", "*.example.com", "www.example.com", " ", "xn--blbr-ura.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(got, ","); s != "*.example.com,www.example.com,xn--blbr-ura.example.com" {
		t.Errorf("names = %s", s)
	}

	bad := map[string]string{
		"192.0.2.1":               "IP addresses",
		"localhost":               "fully qualified",
		"www.*.example.com":       "leftmost label",
		"*foo.example.com":        "leftmost label",
		"-a.example.com":          "hyphen",
		"a..example.com":          "empty",
		"blåbær.example.com":      "A-label",
		"under_score.example.com": "contains",
	}
	for name, want := range bad {
		if _, err := NormaliseNames([]string{name}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	if _, err := NormaliseNames(nil); err == nil {
		t.Error("accepted no names")
	}
	many := make([]string, MaxNames+1)
	for i := range many {
		many[i] = strings.Repeat("a", i%60+1) + ".n" + string(rune('a'+i%26)) + ".example.com"
	}
	if _, err := NormaliseNames(many); err == nil {
		t.Error("accepted more than MaxNames names")
	}
}
