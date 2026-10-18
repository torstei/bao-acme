// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Network is how the engine reaches the outside: an optional forward proxy
// for all HTTP, and the DNS settings for DNS-01 challenges.
type Network struct {
	// Proxy, when set, carries every HTTP request; there is no direct
	// fallback. Proxy environment variables are never consulted.
	Proxy *url.URL
	// ProxyCA is trusted for an https proxy's own certificate, and for the
	// certificates a TLS-inspecting proxy presents for the hosts behind it.
	ProxyCA []*x509.Certificate

	DNS DNSSettings
}

// Propagation check modes.
const (
	PropagationAuthoritative = "authoritative"
	PropagationResolvers     = "resolvers"
	PropagationNone          = "none"
)

// DNSSettings control DNS-01 lookups.
type DNSSettings struct {
	// Resolvers are host:port recursive resolvers for discovery; empty means
	// the host's /etc/resolv.conf.
	Resolvers        []string
	PropagationCheck string
	PropagationDelay time.Duration
	TCPOnly          bool
}

const resolvConf = "/etc/resolv.conf"

// ParseProxyURL accepts an http or https forward proxy, optionally with
// credentials.
func ParseProxyURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("proxy_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("proxy_url must be an http:// or https:// URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy_url has no host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("proxy_url must be just scheme, optional credentials, host and port")
	}
	return u, nil
}

// NormaliseResolver returns a resolver address as host:port, defaulting the
// port to 53.
func NormaliseResolver(s string) (string, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = strings.Trim(s, "[]"), "53"
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return "", fmt.Errorf("%q is not a resolver address", s)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q has an invalid port", s)
	}
	return net.JoinHostPort(host, port), nil
}

// Validate checks that the settings are complete.
func (d DNSSettings) Validate() error {
	switch d.PropagationCheck {
	case PropagationAuthoritative, PropagationResolvers:
	case PropagationNone:
		if d.PropagationDelay <= 0 {
			return errors.New("dns_propagation_check=none needs a dns_propagation_delay")
		}
	default:
		return fmt.Errorf("dns_propagation_check must be %s, %s or %s", PropagationAuthoritative, PropagationResolvers, PropagationNone)
	}
	if d.PropagationDelay < 0 || d.PropagationDelay > time.Hour {
		return errors.New("dns_propagation_delay must be between 0 and 1h")
	}
	return nil
}

// EffectiveResolvers are the resolvers DNS-01 lookups will use: the
// configured ones, or the host's. An empty result means issuance is refused
// rather than falling back to public resolvers.
func (d DNSSettings) EffectiveResolvers() []string {
	if len(d.Resolvers) > 0 {
		return d.Resolvers
	}
	cfg, err := dns.ClientConfigFromFile(resolvConf)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out
}

// HTTPClient returns a client that trusts the system roots plus extraRoots
// and, when a proxy is set, sends everything through it.
func (n *Network) HTTPClient(extraRoots []*x509.Certificate) *http.Client {
	var proxy func(*http.Request) (*url.URL, error)
	var roots []*x509.Certificate
	roots = append(roots, extraRoots...)
	if n != nil && n.Proxy != nil {
		p := n.Proxy
		proxy = func(*http.Request) (*url.URL, error) { return p, nil }
		roots = append(roots, n.ProxyCA...)
	}

	var pool *x509.CertPool
	if len(roots) > 0 {
		var err error
		if pool, err = x509.SystemCertPool(); err != nil {
			pool = x509.NewCertPool()
		}
		for _, c := range roots {
			pool.AddCert(c)
		}
	}

	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy: proxy,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}
