// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// MaxNames is the most names a certificate may have; Let's Encrypt's limit.
const MaxNames = 100

// NormaliseNames validates DNS names for a certificate, as DNS-01 can
// validate them, and returns them lowercased, without trailing dots, sorted
// and without duplicates. A wildcard may only be the leftmost label.
func NormaliseNames(names []string) ([]string, error) {
	var out []string
	for _, raw := range names {
		n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if n == "" {
			continue
		}
		if err := checkName(n); err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		out = append(out, n)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	switch {
	case len(out) == 0:
		return nil, errors.New("at least one name is required")
	case len(out) > MaxNames:
		return nil, fmt.Errorf("at most %d names", MaxNames)
	}
	return out, nil
}

func checkName(n string) error {
	if net.ParseIP(n) != nil {
		return errors.New("IP addresses cannot be validated with DNS-01")
	}
	if len(n) > 253 {
		return errors.New("longer than 253 characters")
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return errors.New("not a fully qualified name")
	}
	for i, l := range labels {
		if l == "*" && i == 0 {
			continue
		}
		if strings.Contains(l, "*") {
			return errors.New("a wildcard may only be the whole leftmost label")
		}
		if l == "" || len(l) > 63 {
			return errors.New("has an empty or too long label")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("a label starts or ends with a hyphen")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("contains %q; use the A-label (xn--) form for international names", c)
			}
		}
	}
	return nil
}
