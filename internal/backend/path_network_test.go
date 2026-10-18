// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
)

func TestNetworkDefaults(t *testing.T) {
	h := newHarness(t)
	n := h.ok(logical.ReadOperation, "config/network", nil)
	if n.Data["proxy_url"] != "" || n.Data["dns_propagation_check"] != "authoritative" || n.Data["dns_tcp_only"] != false {
		t.Errorf("defaults = %v", n.Data)
	}
}

func TestNetworkProxyCredentialsAreWriteOnly(t *testing.T) {
	h := newHarness(t)
	written := h.ok(logical.UpdateOperation, "config/network", map[string]any{"proxy_url": "https://bao:s3cret@proxy.example:8443"})

	for _, resp := range []*logical.Response{written, h.ok(logical.ReadOperation, "config/network", nil)} {
		if resp.Data["proxy_url"] != "https://proxy.example:8443" || resp.Data["proxy_credentials_set"] != true {
			t.Errorf("response = %v", resp.Data)
		}
		if strings.Contains(fmt.Sprint(resp.Data), "s3cret") {
			t.Error("the proxy password was returned")
		}
	}

	stored, err := loadNetwork(context.Background(), h.storage)
	if err != nil || !strings.Contains(stored.ProxyURL, "bao:s3cret@") {
		t.Errorf("credentials not stored: %v, %v", stored, err)
	}

	h.ok(logical.UpdateOperation, "config/network", map[string]any{"proxy_url": ""})
	if n := h.ok(logical.ReadOperation, "config/network", nil); n.Data["proxy_url"] != "" || n.Data["proxy_credentials_set"] != false {
		t.Errorf("after removing the proxy: %v", n.Data)
	}
}

func TestNetworkDNSSettings(t *testing.T) {
	h := newHarness(t)
	n := h.ok(logical.UpdateOperation, "config/network", map[string]any{
		"dns_resolvers":         "10.0.0.53, 10.0.0.54:5353",
		"dns_propagation_check": "resolvers",
		"dns_propagation_delay": "30s",
		"dns_tcp_only":          true,
	})
	if got := strings.Join(n.Data["dns_resolvers"].([]string), ","); got != "10.0.0.53:53,10.0.0.54:5353" {
		t.Errorf("dns_resolvers = %q", got)
	}
	if got := strings.Join(n.Data["effective_dns_resolvers"].([]string), ","); got != "10.0.0.53:53,10.0.0.54:5353" {
		t.Errorf("effective_dns_resolvers = %q", got)
	}
	if n.Data["dns_propagation_check"] != "resolvers" || n.Data["dns_propagation_delay"] != 30 || n.Data["dns_tcp_only"] != true {
		t.Errorf("network = %v", n.Data)
	}

	h.fails(logical.UpdateOperation, "config/network", map[string]any{"dns_propagation_check": "none", "dns_propagation_delay": 0}, "needs a dns_propagation_delay")
	h.ok(logical.UpdateOperation, "config/network", map[string]any{"dns_propagation_check": "none", "dns_propagation_delay": "2m"})

	h.ok(logical.DeleteOperation, "config/network", nil)
	if n := h.ok(logical.ReadOperation, "config/network", nil); n.Data["dns_propagation_check"] != "authoritative" || n.Data["dns_resolvers"] != nil && len(n.Data["dns_resolvers"].([]string)) != 0 {
		t.Errorf("after delete: %v", n.Data)
	}
}

func TestNetworkValidation(t *testing.T) {
	h := newHarness(t)
	cases := map[string]map[string]any{
		"http:// or https://":        {"proxy_url": "socks5://proxy:1080"},
		"just scheme":                {"proxy_url": "http://proxy:3128/path"},
		"proxy_ca_bundle":            {"proxy_ca_bundle": "junk"},
		"dns_resolvers":              {"dns_resolvers": "10.0.0.53:0"},
		"dns_propagation_check must": {"dns_propagation_check": "sometimes"},
		"between 0 and 1h":           {"dns_propagation_delay": "2h"},
	}
	for want, data := range cases {
		h.fails(logical.UpdateOperation, "config/network", data, want)
	}
	if entry, _ := h.storage.Get(context.Background(), networkKey); entry != nil {
		t.Errorf("a rejected write was stored: %s", entry.Value)
	}
}

func TestRegisterUsesProxy(t *testing.T) {
	h := newHarness(t)
	p := acmetest.Start(t, acmetest.Options{})
	proxy := acmetest.StartProxy(t, acmetest.ProxyOptions{TLS: true, User: "bao", Password: "right"})
	h.ok(logical.CreateOperation, "config/accounts/a", map[string]any{
		"directory_url":           p.DirectoryURL,
		"ca_bundle":               p.CAPEM,
		"terms_of_service_agreed": true,
	})

	withCredentials := func(password string) string {
		u := *proxy.URL
		u.User = url.UserPassword("bao", password)
		return u.String()
	}

	h.ok(logical.UpdateOperation, "config/network", map[string]any{
		"proxy_url":       withCredentials("wrong"),
		"proxy_ca_bundle": proxy.CAPEM,
	})
	resp, _ := h.do(logical.UpdateOperation, "config/accounts/a/register", nil)
	if resp == nil || !resp.IsError() {
		t.Fatalf("registered although the proxy refused: %v", resp)
	}
	if h.storedAccount("a").Registration != nil {
		t.Fatal("a failed registration was stored")
	}

	h.ok(logical.UpdateOperation, "config/network", map[string]any{"proxy_url": withCredentials("right")})
	if reg := h.ok(logical.UpdateOperation, "config/accounts/a/register", nil); reg.Data["status"] != "valid" {
		t.Fatalf("registered = %v", reg.Data)
	}
	pebble, _ := url.Parse(p.DirectoryURL)
	targets := proxy.Targets()
	if len(targets) == 0 {
		t.Fatal("registration did not go through the proxy")
	}
	for _, target := range targets {
		if target != pebble.Host {
			t.Errorf("tunnelled to %s, want only %s", target, pebble.Host)
		}
	}
}
