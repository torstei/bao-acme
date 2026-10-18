// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/torstei/bao-acme/internal/acmetest"
	"github.com/torstei/bao-acme/internal/cert"
)

func caCerts(t *testing.T, pemData string) []*x509.Certificate {
	t.Helper()
	certs, err := cert.ParseCertificates(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

func pebbleHost(t *testing.T, p *acmetest.Pebble) string {
	t.Helper()
	u, err := url.Parse(p.DirectoryURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestRegisterThroughProxy(t *testing.T) {
	cases := map[string]acmetest.ProxyOptions{
		"http proxy":                {},
		"https proxy":               {TLS: true},
		"https proxy with password": {TLS: true, User: "bao", Password: "s3cret"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			p := acmetest.Start(t, acmetest.Options{})
			proxy := acmetest.StartProxy(t, opts)

			proxyURL := *proxy.URL
			if opts.User != "" {
				proxyURL.User = url.UserPassword(opts.User, opts.Password)
			}
			a := newAccount(t, p)
			a.Network = &Network{Proxy: &proxyURL}
			if opts.TLS {
				a.Network.ProxyCA = caCerts(t, proxy.CAPEM)
			}

			if _, _, err := Register(context.Background(), a, true); err != nil {
				t.Fatal(err)
			}
			targets := proxy.Targets()
			if len(targets) == 0 {
				t.Fatal("nothing went through the proxy")
			}
			for _, target := range targets {
				if target != pebbleHost(t, p) {
					t.Errorf("tunnelled to %s, want only %s", target, pebbleHost(t, p))
				}
			}
		})
	}
}

func TestNoDirectFallback(t *testing.T) {
	p := acmetest.Start(t, acmetest.Options{})
	proxy := acmetest.StartProxy(t, acmetest.ProxyOptions{User: "bao", Password: "right"})

	wrong := *proxy.URL
	wrong.User = url.UserPassword("bao", "wrong")
	a := newAccount(t, p)
	a.Network = &Network{Proxy: &wrong}

	if _, _, err := Register(context.Background(), a, true); err == nil {
		t.Fatal("registered although the proxy refused the request")
	}
	if proxy.Refused() == 0 {
		t.Error("the proxy saw no attempt")
	}
}

// Go's environment proxy skips loopback targets, so a proxy variable and a
// local Pebble would prove nothing; check the transport itself instead.
func TestIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	for name, n := range map[string]*Network{"no network": nil, "no proxy": {}} {
		transport := n.HTTPClient(nil).Transport.(*http.Transport)
		if transport.Proxy != nil {
			t.Errorf("%s: the transport has a proxy function", name)
		}
	}
}

func TestParseProxyURL(t *testing.T) {
	for _, ok := range []string{"http://proxy:3128", "https://user:pw@proxy.example:8443", "http://10.0.0.1:3128/"} {
		if _, err := ParseProxyURL(ok); err != nil {
			t.Errorf("ParseProxyURL(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"socks5://proxy:1080", "proxy:3128", "http://", "http://proxy:3128/path", "http://proxy:3128?x=1"} {
		if _, err := ParseProxyURL(bad); err == nil {
			t.Errorf("ParseProxyURL(%q) accepted", bad)
		}
	}
}

func TestNormaliseResolver(t *testing.T) {
	cases := map[string]string{
		"10.0.0.53":         "10.0.0.53:53",
		"10.0.0.53:5353":    "10.0.0.53:5353",
		"2001:db8::53":      "[2001:db8::53]:53",
		"[2001:db8::53]:54": "[2001:db8::53]:54",
		"dns.example":       "dns.example:53",
	}
	for in, want := range cases {
		if got, err := NormaliseResolver(in); err != nil || got != want {
			t.Errorf("NormaliseResolver(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.53:0", "10.0.0.53:x", "a b"} {
		if _, err := NormaliseResolver(bad); err == nil {
			t.Errorf("NormaliseResolver(%q) accepted", bad)
		}
	}
}

func TestDNSSettingsValidate(t *testing.T) {
	ok := []DNSSettings{
		{PropagationCheck: PropagationAuthoritative},
		{PropagationCheck: PropagationResolvers, PropagationDelay: 10 * time.Second},
		{PropagationCheck: PropagationNone, PropagationDelay: time.Minute},
	}
	for _, d := range ok {
		if err := d.Validate(); err != nil {
			t.Errorf("%+v: %v", d, err)
		}
	}
	bad := map[string]DNSSettings{
		"needs a dns_propagation_delay": {PropagationCheck: PropagationNone},
		"must be":                       {PropagationCheck: "sometimes"},
		"between 0 and 1h":              {PropagationCheck: PropagationAuthoritative, PropagationDelay: 2 * time.Hour},
	}
	for want, d := range bad {
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: err = %v, want %q", d, err, want)
		}
	}
}
