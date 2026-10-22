// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/testcerts"
)

// twoAccounts gives a harness with accounts a and b, neither able to issue,
// and a certificate "shared" imported by a.
func twoAccounts(t *testing.T) (*harness, testcerts.Chain) {
	t.Helper()
	h := newHarness(t)
	h.ok(logical.CreateOperation, "config/accounts/a", nil)
	h.ok(logical.CreateOperation, "config/accounts/b", nil)
	c := testcerts.New(t, testcerts.Options{Names: []string{"shared.example.test"}})
	h.ok(logical.UpdateOperation, "accounts/a/certs/shared/import", map[string]any{"fullchain": c.Fullchain, "privkey": c.Privkey})
	return h, c
}

func TestAnotherAccountCannotReachACertificate(t *testing.T) {
	h, c := twoAccounts(t)

	if read := h.ok(logical.ReadOperation, "accounts/a/certs/shared", nil); read.Data["privkey"] != c.Privkey {
		t.Fatal("the owner cannot read its certificate")
	}
	for _, path := range []string{"", "/info", "/status", "/versions/1"} {
		if resp, _ := h.do(logical.ReadOperation, "accounts/b/certs/shared"+path, nil); resp != nil {
			t.Errorf("b read accounts/b/certs/shared%s: %v", path, resp.Data)
		}
	}
	h.fails(logical.UpdateOperation, "accounts/b/certs/shared/rollback", map[string]any{"version": 1}, "no certificate named")
	h.fails(logical.UpdateOperation, "accounts/b/certs/shared/destroy", map[string]any{"versions": "1"}, "no certificate named")
	h.fails(logical.UpdateOperation, "accounts/b/certs/shared/unmanage", nil, "not managed")
	h.fails(logical.UpdateOperation, "accounts/b/certs/shared/renew", nil, "not managed")

	h.ok(logical.DeleteOperation, "accounts/b/certs/shared", nil)
	if read := h.ok(logical.ReadOperation, "accounts/a/certs/shared", nil); read.Data["privkey"] != c.Privkey {
		t.Error("b's delete removed a's certificate")
	}
	if v, _ := loadVersion(context.Background(), h.storage, certID("a", "shared"), 1); v == nil || v.destroyed() {
		t.Error("b's destroy reached a's key")
	}

	if keys := h.ok(logical.ListOperation, "accounts/a/certs/", nil).Data["keys"].([]string); len(keys) != 1 || keys[0] != "shared" {
		t.Errorf("a's list = %v", keys)
	}
	if keys, ok := h.ok(logical.ListOperation, "accounts/b/certs/", nil).Data["keys"]; ok {
		t.Errorf("b's list = %v", keys)
	}
	if keys, ok := h.ok(logical.ListOperation, "accounts/b/certs/", map[string]any{"covers": "shared.example.test"}).Data["keys"]; ok {
		t.Errorf("b's covers = %v", keys)
	}
}

func TestAnotherAccountCannotUseADNSProvider(t *testing.T) {
	h, _ := twoAccounts(t)
	h.ok(logical.CreateOperation, "accounts/a/dns/dns-a", map[string]any{"type": "domeneshop", "api_token": "t", "api_secret": "s"})

	if resp, _ := h.do(logical.ReadOperation, "accounts/b/dns/dns-a", nil); resp != nil {
		t.Errorf("b read a's DNS provider: %v", resp.Data)
	}
	if keys, ok := h.ok(logical.ListOperation, "accounts/b/dns/", nil).Data["keys"]; ok {
		t.Errorf("b's DNS list = %v", keys)
	}
	h.ok(logical.DeleteOperation, "accounts/b/dns/dns-a", nil)
	if e, _ := loadDNS(context.Background(), h.storage, "a", "dns-a"); e == nil || e.Settings["api_token"] != "t" {
		t.Error("b changed or removed a's DNS provider")
	}

	h.ok(logical.UpdateOperation, "config/accounts/b", map[string]any{"directory_url": "letsencrypt-staging"})
	h.fails(logical.CreateOperation, "accounts/b/certs/b-www", map[string]any{"names": "www.example.test", "dns": "dns-a"}, `account "b" has no DNS provider named "dns-a"`)

	if read := h.ok(logical.ReadOperation, "accounts/a/dns/dns-a", nil); read.Data["account"] != "a" {
		t.Errorf("a's DNS provider = %v", read.Data)
	}
}

func TestNewEntriesRecordTheirAccount(t *testing.T) {
	h, _ := twoAccounts(t)
	ctx := context.Background()
	h.ok(logical.CreateOperation, "accounts/a/dns/dns-a", map[string]any{"type": "domeneshop", "api_token": "t", "api_secret": "s"})

	if m, _ := loadMeta(ctx, h.storage, certID("a", "shared")); m.Account != "a" {
		t.Errorf("certificate account = %q", m.Account)
	}
	if e, _ := loadDNS(ctx, h.storage, "a", "dns-a"); e.Account != "a" {
		t.Errorf("DNS provider account = %q", e.Account)
	}
	c := testcerts.New(t, testcerts.Options{})
	h.fails(logical.UpdateOperation, "accounts/nobody/certs/x/import", map[string]any{"fullchain": c.Fullchain, "privkey": c.Privkey}, `no account named "nobody"`)
	h.fails(logical.CreateOperation, "accounts/nobody/dns/x", map[string]any{"type": "domeneshop", "api_token": "t", "api_secret": "s"}, `no account named "nobody"`)
}

func TestStatusByAccount(t *testing.T) {
	h, _ := twoAccounts(t)
	h.ok(logical.UpdateOperation, "accounts/b/certs/b-only/import", func() map[string]any {
		c := testcerts.New(t, testcerts.Options{NotAfter: time.Now().Add(24 * time.Hour)})
		return map[string]any{"fullchain": c.Fullchain, "privkey": c.Privkey}
	}())

	mount := h.ok(logical.ReadOperation, "status", nil)
	certs := mount.Data["certificates"].(map[string]any)
	if mount.Data["total"] != 2 || certs["a/shared"].(map[string]any)["account"] != "a" || certs["b/b-only"].(map[string]any)["account"] != "b" {
		t.Errorf("mount status = %v", mount.Data)
	}
	scoped := h.ok(logical.ReadOperation, "accounts/a/status", nil)
	if scoped.Data["total"] != 1 || scoped.Data["certificates"].(map[string]any)["shared"] == nil {
		t.Errorf("a's status = %v", scoped.Data)
	}
}

func TestDeletesRefusedWhileInUse(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))

	resp, _ := e.do(logical.DeleteOperation, "config/dns/bind", nil)
	if resp == nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "in use by www") {
		t.Errorf("deleting a DNS provider in use: %v", resp)
	}
	resp, _ = e.do(logical.DeleteOperation, "config/accounts/le", nil)
	if resp == nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "certificate www") || !strings.Contains(resp.Error().Error(), "DNS provider bind") {
		t.Errorf("deleting an account in use: %v", resp)
	}

	e.ok(logical.UpdateOperation, "certs/www/unmanage", nil)
	if err := putJSON(context.Background(), e.storage, inflightKey(e.id("www")), &inflightEntry{
		Account: "le", DNS: "bind",
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", KeyAuth: testKeyAuth}},
	}); err != nil {
		t.Fatal(err)
	}
	resp, _ = e.do(logical.DeleteOperation, "config/dns/bind", nil)
	if resp == nil || !resp.IsError() || !strings.Contains(resp.Error().Error(), "leftover challenge records") {
		t.Errorf("deleting a DNS provider an in-flight entry needs: %v", resp)
	}

	e.ok(logical.DeleteOperation, "certs/www", nil)
	e.ok(logical.DeleteOperation, "config/dns/bind", nil)
	e.ok(logical.DeleteOperation, "config/accounts/le", nil)
	if a, _ := loadAccount(context.Background(), e.storage, "le"); a != nil {
		t.Error("the account was not deleted once it owned nothing")
	}
}

// TestNamesArePerAccount: two accounts can use the same certificate and
// DNS provider names, and each keeps its own.
func TestNamesArePerAccount(t *testing.T) {
	h, c := twoAccounts(t)
	other := testcerts.New(t, testcerts.Options{Names: []string{"other.example.test"}})
	h.ok(logical.UpdateOperation, "accounts/b/certs/shared/import", map[string]any{"fullchain": other.Fullchain, "privkey": other.Privkey})
	h.ok(logical.CreateOperation, "accounts/a/dns/dns", map[string]any{"type": "domeneshop", "api_token": "a-token", "api_secret": "s"})
	h.ok(logical.CreateOperation, "accounts/b/dns/dns", map[string]any{"type": "domeneshop", "api_token": "b-token", "api_secret": "s"})

	if read := h.ok(logical.ReadOperation, "accounts/a/certs/shared", nil); read.Data["privkey"] != c.Privkey {
		t.Error("b's certificate replaced a's")
	}
	if read := h.ok(logical.ReadOperation, "accounts/b/certs/shared", nil); read.Data["privkey"] != other.Privkey {
		t.Error("b does not read its own certificate")
	}
	for account, token := range map[string]string{"a": "a-token", "b": "b-token"} {
		if e, _ := loadDNS(context.Background(), h.storage, account, "dns"); e == nil || e.Settings["api_token"] != token {
			t.Errorf("%s's DNS provider = %v", account, e)
		}
	}

	certs := h.ok(logical.ReadOperation, "status", nil).Data["certificates"].(map[string]any)
	if len(certs) != 2 || certs["a/shared"] == nil || certs["b/shared"] == nil {
		t.Errorf("mount status certificates = %v", certs)
	}

	h.ok(logical.DeleteOperation, "accounts/b/certs/shared", nil)
	h.ok(logical.ReadOperation, "accounts/a/certs/shared", nil)
	h.ok(logical.DeleteOperation, "accounts/b/dns/dns", nil)
	h.ok(logical.DeleteOperation, "config/accounts/b", nil)
}

// TestOldLayoutIsIgnored: entries stored before v0.5.0 are neither read nor
// counted, and do not stop the mount from starting.
func TestOldLayoutIsIgnored(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := putJSON(ctx, h.storage, "certs/old/meta", &certMeta{Account: "t", CurrentVersion: 1, LatestVersion: 1, MaxVersions: 3}); err != nil {
		t.Fatal(err)
	}
	if err := h.b.Initialize(ctx, &logical.InitializationRequest{Storage: h.storage}); err != nil {
		t.Fatalf("initialize with old entries: %v", err)
	}
	if s := h.ok(logical.ReadOperation, "status", nil); s.Data["total"] != 0 {
		t.Errorf("status counts an old entry: %v", s.Data)
	}
	if resp, _ := h.do(logical.ReadOperation, "accounts/t/certs/old/info", nil); resp != nil {
		t.Errorf("an old entry is read: %v", resp.Data)
	}
}

func TestOldPathsAreGone(t *testing.T) {
	h, _ := twoAccounts(t)
	for _, path := range []string{"certs/", "certs/shared", "certs/shared/info", "config/dns/", "config/dns/x", "accounts/a"} {
		op := logical.ReadOperation
		if strings.HasSuffix(path, "/") {
			op = logical.ListOperation
		}
		_, err := h.b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Storage: h.storage})
		if err == nil || !strings.Contains(err.Error(), "unsupported path") {
			t.Errorf("%s %s: err = %v, want unsupported path", op, path, err)
		}
	}
}
