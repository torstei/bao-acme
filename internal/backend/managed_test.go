// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

const (
	managedZone       = "example.test"
	managedTSIGName   = "bao-acme."
	managedTSIGSecret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
)

type managedEnv struct {
	*harness
	dns *acmetest.DNS
}

// newManagedEnv configures an account (agreed, not yet registered), the
// network and a dnsupdate provider against an in-process Pebble and DNS
// server.
func newManagedEnv(t *testing.T) *managedEnv {
	t.Helper()
	h := newHarness(t)
	d := acmetest.StartDNS(t, &acmetest.TSIG{Name: managedTSIGName, Secret: managedTSIGSecret}, managedZone)
	p := acmetest.Start(t, acmetest.Options{Resolver: d.Addr})

	h.ok(logical.CreateOperation, "config/accounts/le", map[string]any{
		"directory_url":           p.DirectoryURL,
		"ca_bundle":               p.CAPEM,
		"terms_of_service_agreed": true,
	})
	h.account = "le"
	h.ok(logical.UpdateOperation, "config/network", map[string]any{
		"dns_resolvers":         d.Addr,
		"dns_propagation_check": "resolvers",
	})
	h.ok(logical.CreateOperation, "config/dns/bind", map[string]any{
		"type":                "dnsupdate",
		"nameserver":          d.Addr,
		"tsig_key":            managedTSIGName,
		"tsig_secret":         managedTSIGSecret,
		"propagation_timeout": "10s",
		"polling_interval":    "1s",
	})
	return &managedEnv{harness: h, dns: d}
}

func (e *managedEnv) define(name string, names ...string) *logical.Response {
	e.t.Helper()
	return e.ok(logical.CreateOperation, "certs/"+name, map[string]any{
		"names": strings.Join(names, ","),
		"dns":   "bind",
	})
}

// waitFor polls the certificate's meta until cond holds.
func (e *managedEnv) waitFor(name string, what string, cond func(*certMeta) bool) *certMeta {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		m, err := loadMeta(context.Background(), e.storage, name)
		if err != nil {
			e.t.Fatal(err)
		}
		if m != nil && cond(m) {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	m, _ := loadMeta(context.Background(), e.storage, name)
	e.t.Fatalf("%s: timed out waiting for %s; meta = %+v, issuance = %+v", name, what, m, m.Issuance)
	return nil
}

func hasVersion(n int) func(*certMeta) bool {
	return func(m *certMeta) bool { return m.CurrentVersion == n }
}

func TestManagedIssuance(t *testing.T) {
	e := newManagedEnv(t)

	defined := e.define("www", "www.example.test", "*.www.example.test")
	if defined.Data["issuing"] != true {
		t.Fatalf("defined = %v", defined.Data)
	}
	e.waitFor("www", "the first certificate", hasVersion(1))

	info := e.ok(logical.ReadOperation, "certs/www/info", nil)
	if info.Data["source"] != "acme:le" || info.Data["managed"] != true {
		t.Errorf("info = %v", info.Data)
	}
	if got := strings.Join(info.Data["names"].([]string), ","); got != "*.www.example.test,www.example.test" {
		t.Errorf("names = %s", got)
	}
	issuance := info.Data["issuance"].(map[string]any)
	if issuance["needed"] != "" || issuance["failures"] != 0 || issuance["last_success_time"].(time.Time).IsZero() {
		t.Errorf("issuance = %v", issuance)
	}

	read := e.ok(logical.ReadOperation, "certs/www", nil)
	if _, err := cert.Parse(read.Data["fullchain"].(string), read.Data["privkey"].(string), time.Now()); err != nil {
		t.Errorf("issued certificate does not validate: %v", err)
	}
	if acct := e.ok(logical.ReadOperation, "config/accounts/le", nil); acct.Data["registered"] != true {
		t.Error("the account was not registered on first use")
	}
	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 0 {
		t.Errorf("challenge records left behind: %v", got)
	}

	if again := e.define("www", "www.example.test", "*.www.example.test"); again.Data["issuing"] != nil {
		t.Errorf("an unchanged definition started an issuance: %v", again.Data)
	}
}

func TestImportedBecomesManaged(t *testing.T) {
	e := newManagedEnv(t)
	old := testcerts.New(t, testcerts.Options{Names: []string{"old.example.test"}})
	e.imp("site", old)

	e.define("site", "site.example.test")
	if read := e.ok(logical.ReadOperation, "certs/site", nil); read.Data["privkey"] != old.Privkey {
		t.Error("the imported version was not served while the first issuance was pending")
	}
	e.waitFor("site", "the issued version", hasVersion(2))

	info := e.ok(logical.ReadOperation, "certs/site/info", nil)
	if info.Data["source"] != "acme:le" || len(info.Data["versions"].(map[string]any)) != 2 {
		t.Errorf("info = %v", info.Data)
	}
	v1 := e.ok(logical.ReadOperation, "certs/site/versions/1", nil)
	if v1.Data["source"] != "import" {
		t.Errorf("version 1 = %v", v1.Data["source"])
	}
}

func TestMatchingImportNeedsNoIssuance(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("site", testcerts.New(t, testcerts.Options{Names: []string{"site.example.test"}}))

	defined := e.define("site", "site.example.test")
	if defined.Data["issuing"] != nil {
		t.Fatalf("issuing for a certificate that already matches: %v", defined.Data)
	}
	if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if m, _ := loadMeta(context.Background(), e.storage, "site"); m.CurrentVersion != 1 || m.Issuance != nil {
		t.Errorf("meta = %+v", m)
	}
}

func TestIssuanceFailureBacksOff(t *testing.T) {
	e := newManagedEnv(t)
	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})

	e.define("www", "www.example.test")
	m := e.waitFor("www", "a recorded failure", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures == 1 })
	if m.Issuance.LastError == "" || !m.Issuance.NextAttemptTime.After(time.Now()) || m.CurrentVersion != 0 {
		t.Fatalf("issuance = %+v", m.Issuance)
	}

	if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if m, _ := loadMeta(context.Background(), e.storage, "www"); m.Issuance.Failures != 1 {
		t.Errorf("retried before the backoff ended: %+v", m.Issuance)
	}

	info := e.ok(logical.ReadOperation, "certs/www/info", nil)
	if info.Data["issuance"].(map[string]any)["last_error"] == "" {
		t.Errorf("info = %v", info.Data)
	}
	if resp, _ := e.do(logical.ReadOperation, "certs/www", nil); resp != nil {
		t.Errorf("read before any certificate exists = %v", resp.Data)
	}
}

func TestPeriodicResumesAfterRestart(t *testing.T) {
	e := newManagedEnv(t)
	if err := putJSON(context.Background(), e.storage, metaKey("www"), &certMeta{
		MaxVersions: defaultMaxVersions,
		Managed: &managedSpec{
			Names: []string{"www.example.test"}, KeyType: "ecdsa-p256", Account: "le", DNS: "bind",
			DefinedTime: time.Now(),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
		t.Fatal(err)
	}
	e.waitFor("www", "the certificate", hasVersion(1))
}

func TestDefineValidation(t *testing.T) {
	e := newManagedEnv(t)
	base := map[string]any{"names": "www.example.test", "dns": "bind"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	cases := map[string]map[string]any{
		"names is required":     with("names", nil),
		"IP addresses":          with("names", "192.0.2.1"),
		"leftmost label":        with("names", "www.*.example.test"),
		"A-label":               with("names", "blåbær.example.test"),
		`no DNS provider named`: with("dns", "nope"),
		"unsupported key_type":  with("key_type", "dsa-1024"),
		"dns is required":       with("dns", nil),
	}
	old := with("dns", nil)
	old["dns_provider"] = "bind"
	e.fails(logical.CreateOperation, "certs/old", old, "dns is required")
	for want, data := range cases {
		e.fails(logical.CreateOperation, "certs/x", data, want)
	}
	if resp, _ := e.do(logical.ReadOperation, "certs/x/info", nil); resp != nil {
		t.Error("a rejected definition was stored")
	}
	e.fails(logical.CreateOperation, "accounts/nope/certs/x", base, `no account named "nope"`)
	e.fails(logical.CreateOperation, "accounts/t/certs/x", base, `account "t" has no directory_url`)
}

func TestUnmanage(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))

	e.ok(logical.UpdateOperation, "certs/www/unmanage", nil)
	info := e.ok(logical.ReadOperation, "certs/www/info", nil)
	if info.Data["managed"] != false || info.Data["current_version"] != 1 {
		t.Errorf("after unmanage: %v", info.Data)
	}
	e.imp("www", testcerts.New(t, testcerts.Options{Names: []string{"www.example.test"}}))
	e.fails(logical.UpdateOperation, "certs/www/unmanage", nil, "not managed")

	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.define("never", "never.example.test")
	e.waitFor("never", "a failure", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures > 0 })
	e.ok(logical.UpdateOperation, "certs/never/unmanage", nil)
	if m, _ := loadMeta(context.Background(), e.storage, "never"); m != nil {
		t.Errorf("an unmanaged certificate without versions was kept: %+v", m)
	}
}

func TestRollbackOfManagedMustMatch(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("site", testcerts.New(t, testcerts.Options{Names: []string{"old.example.test"}}))
	e.define("site", "site.example.test")
	e.waitFor("site", "the issued version", hasVersion(2))

	e.fails(logical.UpdateOperation, "certs/site/rollback", map[string]any{"version": 1}, "does not match the managed definition")
}

func TestBackoffGrows(t *testing.T) {
	prev := time.Duration(0)
	for f := 1; f <= 12; f++ {
		d := backoff(f)
		if d < firstBackoff*9/10 || d > maxBackoff*11/10 {
			t.Errorf("backoff(%d) = %v", f, d)
		}
		if f <= 8 && d < prev*3/2 {
			t.Errorf("backoff(%d) = %v did not grow from %v", f, d, prev)
		}
		prev = d
	}
}
