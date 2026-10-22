// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
)

func TestDNSProviderLifecycle(t *testing.T) {
	h := newHarness(t)

	created := h.ok(logical.CreateOperation, "config/dns/domeneshop", map[string]any{
		"type":       "domeneshop",
		"api_token":  "tok-123",
		"api_secret": "sec-456",
	})
	if created.Data["type"] != "domeneshop" || created.Data["api_token_set"] != true || created.Data["api_secret_set"] != true {
		t.Fatalf("created = %v", created.Data)
	}
	if _, ok := created.Data["provider"]; ok {
		t.Error("read shows the old field provider")
	}
	if created.Data["egress"] != "HTTPS to api.domeneshop.no" {
		t.Errorf("egress = %v", created.Data["egress"])
	}
	read := h.ok(logical.ReadOperation, "config/dns/domeneshop", nil)
	for _, resp := range []*logical.Response{created, read} {
		if s := fmt.Sprint(resp.Data); strings.Contains(s, "tok-123") || strings.Contains(s, "sec-456") {
			t.Errorf("credentials returned: %s", s)
		}
	}

	h.ok(logical.UpdateOperation, "config/dns/domeneshop", map[string]any{"api_secret": "sec-789", "propagation_timeout": "10m"})
	stored, err := loadDNS(context.Background(), h.storage, h.account, "domeneshop")
	if err != nil || stored.Settings["api_token"] != "tok-123" || stored.Settings["api_secret"] != "sec-789" || stored.PropagationTimeoutSeconds != 600 {
		t.Errorf("after a partial update: %+v, %v", stored, err)
	}

	h.fails(logical.UpdateOperation, "config/dns/domeneshop", map[string]any{"api_secret": ""}, "needs api_secret")
	h.fails(logical.UpdateOperation, "config/dns/domeneshop", map[string]any{"type": "cloudflare"}, "cannot change")
	h.fails(logical.UpdateOperation, "config/dns/domeneshop", map[string]any{"nameserver": "ns.example"}, `no setting "nameserver"`)
	if stored, _ := loadDNS(context.Background(), h.storage, h.account, "domeneshop"); stored.Settings["api_secret"] != "sec-789" {
		t.Error("a rejected update changed the stored settings")
	}

	if keys := h.ok(logical.ListOperation, "config/dns/", nil).Data["keys"].([]string); len(keys) != 1 || keys[0] != "domeneshop" {
		t.Errorf("list = %v", keys)
	}
	h.ok(logical.DeleteOperation, "config/dns/domeneshop", nil)
	if resp, _ := h.do(logical.ReadOperation, "config/dns/domeneshop", nil); resp != nil {
		t.Error("still readable after delete")
	}
}

func TestDNSProviderValidation(t *testing.T) {
	h := newHarness(t)
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"api_token": "t"}, "type is required")
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"provider": "domeneshop", "api_token": "t", "api_secret": "s"}, "type is required")
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"type": "route66"}, "unknown type")
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"type": "domeneshop", "api_token": "t"}, "needs api_secret")
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"type": "cloudflare", "email": "a@b.c"}, "set together")
	h.fails(logical.CreateOperation, "config/dns/x", map[string]any{"type": "dnsupdate", "nameserver": "ns", "tsig_algorithm": "hmac-md5"}, "tsig_algorithm")
	if resp, _ := h.do(logical.ReadOperation, "config/dns/x", nil); resp != nil {
		t.Error("a rejected create was stored")
	}
}

func TestDNSUpdateNotProxiedWarning(t *testing.T) {
	h := newHarness(t)
	h.ok(logical.UpdateOperation, "config/network", map[string]any{"proxy_url": "http://proxy.example:3128"})

	resp := h.ok(logical.CreateOperation, "config/dns/bind", map[string]any{"type": "dnsupdate", "nameserver": "10.0.0.53"})
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "does not go through the proxy") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	if resp := h.ok(logical.CreateOperation, "config/dns/ds", map[string]any{"type": "domeneshop", "api_token": "t", "api_secret": "s"}); len(resp.Warnings) != 0 {
		t.Errorf("warnings for an HTTP provider = %v", resp.Warnings)
	}
}

func TestStoredDNSProviderPublishes(t *testing.T) {
	h := newHarness(t)
	const tsigName, tsigSecret = "bao-acme.", "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
	d := acmetest.StartDNS(t, &acmetest.TSIG{Name: tsigName, Secret: tsigSecret}, "example.test")
	prev := dns01.DefaultClient()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: []string{d.Addr}}))
	t.Cleanup(func() { dns01.SetDefaultClient(prev) })

	h.ok(logical.CreateOperation, "config/dns/bind", map[string]any{
		"type": "dnsupdate", "nameserver": d.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret,
	})
	e, err := loadDNS(context.Background(), h.storage, h.account, "bind")
	if err != nil {
		t.Fatal(err)
	}
	n, err := loadNetwork(context.Background(), h.storage)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.provider(n)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present(context.Background(), "www.example.test", "", "token.thumbprint"); err != nil {
		t.Fatal(err)
	}
	if got := d.TXT("_acme-challenge.www.example.test"); len(got) != 1 {
		t.Errorf("TXT = %v", got)
	}
}
