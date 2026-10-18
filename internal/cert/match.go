// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"net"
	"strings"
)

// Covers reports whether any of names covers host. A wildcard covers exactly
// one label: "*.example.com" covers "a.example.com", but neither
// "example.com" nor "a.b.example.com". IP addresses match only exactly.
func Covers(names []string, host string) bool {
	host = normaliseHost(host)
	if host == "" {
		return false
	}
	hostIP := net.ParseIP(host)
	for _, n := range names {
		if hostIP != nil {
			if ip := net.ParseIP(n); ip != nil && ip.Equal(hostIP) {
				return true
			}
			continue
		}
		if coversName(normaliseHost(n), host) {
			return true
		}
	}
	return false
}

func coversName(name, host string) bool {
	if name == host {
		return true
	}
	suffix, ok := strings.CutPrefix(name, "*.")
	if !ok {
		return false
	}
	label, rest, ok := strings.Cut(host, ".")
	return ok && label != "" && rest == suffix
}

func normaliseHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}
