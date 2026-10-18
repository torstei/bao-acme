// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

// testdata/storage-v1 holds entries exactly as storage format 1 (design
// §5.6) writes them, one file per storage key. A file is frozen once a
// release has shipped it: never regenerate it. A format change adds a new
// directory beside this one.
const storageV1 = "testdata/storage-v1"

func loadFixture(t *testing.T, h *harness, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		key, _ := filepath.Rel(dir, path)
		return h.storage.Put(context.Background(), &logical.StorageEntry{Key: filepath.ToSlash(key), Value: value})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, key string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(storageV1, key))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReadsStorageV1(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)
	stored := readFixture(t, "certs/example.com/versions/2")

	read := h.ok(logical.ReadOperation, "certs/example.com", nil)
	if read.Data["fullchain"] != stored["certificate"].(string)+stored["chain"].(string) {
		t.Error("fullchain is not certificate followed by chain")
	}
	if read.Data["privkey"] != stored["privkey"] || read.Data["version"] != 2 {
		t.Errorf("read = %v", read.Data)
	}

	info := h.ok(logical.ReadOperation, "certs/example.com/info", nil)
	desc := stored["description"].(map[string]any)
	if info.Data["sha256"] != desc["sha256"] || info.Data["max_versions"] != 3 {
		t.Errorf("info = %v", info.Data)
	}
	if v1 := info.Data["versions"].(map[string]any)["1"].(map[string]any); v1["destroyed"] != true {
		t.Errorf("version 1 = %v", v1)
	}
	h.fails(logical.ReadOperation, "certs/example.com/versions/1", nil, "destroyed")

	if got := h.ok(logical.ListOperation, "certs/", map[string]any{"covers": "www.example.com"}).Data["keys"]; len(got.([]string)) != 1 {
		t.Errorf("covers = %v", got)
	}
}

func TestReadsStorageV1Account(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)
	stored := readFixture(t, "config/accounts/example")
	reg := stored["registration"].(map[string]any)

	read := h.ok(logical.ReadOperation, "config/accounts/example", nil)
	for field, want := range map[string]any{
		"directory_url":           stored["directory_url"],
		"email":                   stored["email"],
		"key_type":                stored["key_type"],
		"eab_kid":                 stored["eab_kid"],
		"eab_hmac_key_set":        true,
		"terms_of_service_agreed": true,
		"registered":              true,
		"account_url":             reg["account_url"],
		"status":                  reg["status"],
	} {
		if got := read.Data[field]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	if recs, _ := read.Data["caa_records"].([]string); len(recs) != 2 || !strings.Contains(recs[0], "accounturi="+reg["account_url"].(string)) {
		t.Errorf("caa_records = %v", read.Data["caa_records"])
	}
	client, err := h.storedAccount("example").client()
	if err != nil || client.Key == nil || len(client.CABundle) != 1 || client.AccountURL != reg["account_url"] {
		t.Errorf("stored account does not load: %+v, %v", client, err)
	}
}

func TestWritesStorageV1AccountFields(t *testing.T) {
	h := newHarness(t)
	p := acmetest.Start(t, acmetest.Options{EABKeys: map[string]string{testEABKeyID: testEABHMAC}})
	h.ok(logical.CreateOperation, "config/accounts/example", map[string]any{
		"directory_url":           p.DirectoryURL,
		"email":                   "ops@example.com",
		"ca_bundle":               p.CAPEM,
		"terms_of_service_agreed": true,
		"eab_kid":                 testEABKeyID,
		"eab_hmac_key":            testEABHMAC,
	})
	h.ok(logical.UpdateOperation, "config/accounts/example/register", nil)

	entry, err := h.storage.Get(context.Background(), "config/accounts/example")
	if err != nil || entry == nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(entry.Value, &got); err != nil {
		t.Fatal(err)
	}
	missingFields(t, "config/accounts/example", readFixture(t, "config/accounts/example"), got)
}

func TestReadsStorageV1Network(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)

	n := h.ok(logical.ReadOperation, "config/network", nil)
	if n.Data["proxy_url"] != "https://proxy.example:8443" || n.Data["proxy_credentials_set"] != true {
		t.Errorf("proxy = %v, %v", n.Data["proxy_url"], n.Data["proxy_credentials_set"])
	}
	if n.Data["dns_propagation_check"] != "resolvers" || n.Data["dns_propagation_delay"] != 30 || n.Data["dns_tcp_only"] != true {
		t.Errorf("dns = %v", n.Data)
	}
	stored, err := loadNetwork(context.Background(), h.storage)
	if err != nil {
		t.Fatal(err)
	}
	network, err := stored.network()
	if err != nil || network.Proxy.User.Username() != "bao" || len(network.ProxyCA) != 1 || len(network.DNS.Resolvers) != 1 {
		t.Errorf("stored network does not load: %+v, %v", network, err)
	}
}

func TestWritesStorageV1NetworkFields(t *testing.T) {
	h := newHarness(t)
	proxy := acmetest.StartProxy(t, acmetest.ProxyOptions{TLS: true})
	h.ok(logical.UpdateOperation, "config/network", map[string]any{
		"proxy_url":             "https://bao:s3cret@proxy.example:8443",
		"proxy_ca_bundle":       proxy.CAPEM,
		"dns_resolvers":         "10.0.0.53",
		"dns_propagation_check": "resolvers",
		"dns_propagation_delay": "30s",
		"dns_tcp_only":          true,
	})
	entry, err := h.storage.Get(context.Background(), "config/network")
	if err != nil || entry == nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(entry.Value, &got); err != nil {
		t.Fatal(err)
	}
	missingFields(t, "config/network", readFixture(t, "config/network"), got)
}

func TestReadsStorageV1DNS(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)

	read := h.ok(logical.ReadOperation, "config/dns/example", nil)
	for field, want := range map[string]any{
		"provider":            "domeneshop",
		"api_token_set":       true,
		"api_secret_set":      true,
		"ttl":                 300,
		"propagation_timeout": 600,
		"polling_interval":    30,
	} {
		if got := read.Data[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	e, err := loadDNS(context.Background(), h.storage, "example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.provider(&networkEntry{}); err != nil {
		t.Errorf("stored provider does not build: %v", err)
	}
}

func TestWritesStorageV1DNSFields(t *testing.T) {
	h := newHarness(t)
	h.ok(logical.CreateOperation, "config/dns/example", map[string]any{
		"provider": "domeneshop", "api_token": "tok-123", "api_secret": "sec-456",
		"ttl": 300, "propagation_timeout": "10m", "polling_interval": "30s",
	})
	entry, err := h.storage.Get(context.Background(), "config/dns/example")
	if err != nil || entry == nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(entry.Value, &got); err != nil {
		t.Fatal(err)
	}
	missingFields(t, "config/dns/example", readFixture(t, "config/dns/example"), got)
}

func TestReadsStorageV1Managed(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)

	info := h.ok(logical.ReadOperation, "certs/managed/info", nil)
	def := info.Data["definition"].(map[string]any)
	if info.Data["managed"] != true || info.Data["source"] != "acme:le" || def["account"] != "le" || def["dns_provider"] != "bind" {
		t.Errorf("managed info = %v", info.Data)
	}
	issuance := info.Data["issuance"].(map[string]any)
	if issuance["last_success_time"].(time.Time).IsZero() || issuance["needed"] != "" {
		t.Errorf("managed issuance = %v", issuance)
	}
	if renewal, _ := issuance["renewal"].(map[string]any); renewal["source"] != scheduleARI || renewal["renew_at"].(time.Time).IsZero() || renewal["window_end"].(time.Time).IsZero() {
		t.Errorf("managed renewal = %v", issuance["renewal"])
	}

	failing := h.ok(logical.ReadOperation, "certs/failing/info", nil)
	issuance = failing.Data["issuance"].(map[string]any)
	if issuance["failures"] != 2 || issuance["renew_requested"] != true || issuance["last_error"] == "" || issuance["needed"] != "no certificate yet" || issuance["next_attempt_time"].(time.Time).IsZero() {
		t.Errorf("failing issuance = %v", issuance)
	}
}

func freshMeta(t *testing.T, e *managedEnv, name string) map[string]any {
	t.Helper()
	entry, err := e.storage.Get(context.Background(), metaKey(name))
	if err != nil || entry == nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(entry.Value, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWritesStorageV1ManagedFields(t *testing.T) {
	e := newManagedEnv(t)
	e.define("managed", "managed.example.test")
	e.waitFor("managed", "the certificate and its schedule", func(m *certMeta) bool { return m.CurrentVersion == 1 && m.Renewal != nil })
	missingFields(t, "certs/managed/meta", readFixture(t, "certs/managed/meta"), freshMeta(t, e, "managed"))

	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.define("failing", "failing.example.test")
	e.waitFor("failing", "a failure", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures == 1 })
	e.ok(logical.UpdateOperation, "certs/failing/renew", nil)
	e.waitFor("failing", "a second failure", func(m *certMeta) bool { return m.Issuance.Failures == 2 })
	missingFields(t, "certs/failing/meta", readFixture(t, "certs/failing/meta"), freshMeta(t, e, "failing"))
}

func TestReadsStorageV1AttemptHistory(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)

	s := h.ok(logical.ReadOperation, "certs/history/status", nil)
	attempts := s.Data["attempts"].([]map[string]any)
	if len(attempts) != 2 || attempts[0]["outcome"] != "failed" || attempts[0]["error"] == "" ||
		attempts[1]["outcome"] != "issued" || attempts[1]["version"] != 1 || attempts[1]["duration_seconds"].(float64) <= 0 {
		t.Errorf("attempts = %v", attempts)
	}
	if s.Data["state"] != stateFailing {
		t.Errorf("state = %v", s.Data["state"])
	}
}

func TestWritesStorageV1AttemptHistoryFields(t *testing.T) {
	e := newManagedEnv(t)
	e.define("history", "history.example.test")
	e.waitFor("history", "the certificate and its schedule", func(m *certMeta) bool { return m.CurrentVersion == 1 && m.Renewal != nil })
	e.ok(logical.DeleteOperation, "config/dns/bind", nil)
	e.ok(logical.UpdateOperation, "certs/history/renew", nil)
	e.waitFor("history", "a failed renewal", func(m *certMeta) bool { return m.Issuance.Failures == 1 })

	got := freshMeta(t, e, "history")
	want := readFixture(t, "certs/history/meta")
	missingFields(t, "certs/history/meta", want, got)
	for i, a := range want["issuance"].(map[string]any)["attempts"].([]any) {
		missingFields(t, fmt.Sprintf("certs/history/meta attempt %d", i), a.(map[string]any), got["issuance"].(map[string]any)["attempts"].([]any)[i].(map[string]any))
	}
}

func TestReadsStorageV1Inflight(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)
	ctx := context.Background()

	ordering, err := loadInflight(ctx, h.storage, "ordering")
	if err != nil || ordering == nil {
		t.Fatalf("ordering: %+v, %v", ordering, err)
	}
	if _, err := cert.ParseKey(ordering.Privkey); err != nil || ordering.OrderURL == "" || len(ordering.Published) != 2 || ordering.Published[1].PresentError == "" {
		t.Errorf("ordering = %+v, key error %v", ordering, err)
	}
	if !inflightDue(ordering, time.Now()) {
		t.Error("an interrupted order is not due for recovery")
	}

	s := h.ok(logical.ReadOperation, "certs/leftover/status", nil)
	published := s.Data["inflight"].(map[string]any)["published"].([]map[string]any)
	if len(published) != 1 || published[0]["cleanup_error"] == "" {
		t.Errorf("leftover status = %v", s.Data["inflight"])
	}
}

func freshInflight(t *testing.T, e *managedEnv, name string) map[string]any {
	t.Helper()
	entry, err := e.storage.Get(context.Background(), inflightKey(name))
	if err != nil || entry == nil {
		t.Fatalf("%s: %v", name, err)
	}
	var got map[string]any
	if err := json.Unmarshal(entry.Value, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWritesStorageV1InflightFields(t *testing.T) {
	e := newManagedEnv(t)
	ctx := context.Background()
	e.b.issuer.stop()

	e.defineQuietly("ordering", "ordering.example.test", "www.ordering.example.test")
	if claim, err := e.b.claimIssuance(ctx, e.storage, "ordering"); err != nil || claim == nil {
		t.Fatalf("claim = %v, %v", claim, err)
	}
	dnsEntry, _ := loadDNS(ctx, e.storage, "bind")
	good, _ := dnsEntry.provider(&networkEntry{})
	if err := e.b.recording(good, e.storage, "ordering").Present(ctx, "ordering.example.test", "tok1", "tok1.thumb"); err != nil {
		t.Fatal(err)
	}
	dnsEntry.Settings["tsig_secret"] = "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="
	bad, _ := dnsEntry.provider(&networkEntry{})
	if err := e.b.recording(bad, e.storage, "ordering").Present(ctx, "www.ordering.example.test", "tok2", "tok2.thumb"); err == nil {
		t.Fatal("setup: a refused update succeeded")
	}
	if err := e.b.updateInflight(ctx, e.storage, "ordering", func(i *inflightEntry) { i.OrderURL = "https://ca.example/order/1" }); err != nil {
		t.Fatal(err)
	}
	got := freshInflight(t, e, "ordering")
	want := readFixture(t, "certs/ordering/inflight")
	missingFields(t, "certs/ordering/inflight", want, got)
	for i, rec := range want["published"].([]any) {
		missingFields(t, fmt.Sprintf("certs/ordering/inflight published %d", i), rec.(map[string]any), got["published"].([]any)[i].(map[string]any))
	}

	e.imp("leftover", testcerts.New(t, testcerts.Options{Names: []string{"leftover.example.test"}}))
	spec := e.defineQuietly("leftover", "leftover.example.test")
	e.ok(logical.DeleteOperation, "config/dns/bind", nil)
	if err := putJSON(ctx, e.storage, inflightKey("leftover"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Reason: "renewal is due", Account: "le", DNSProvider: "bind",
		Published: []publishedRecord{{Domain: "leftover.example.test", Token: "tok", KeyAuth: "tok.thumb", PublishedTime: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.b.recover(ctx, e.storage, "leftover"); err != nil {
		t.Fatal(err)
	}
	got = freshInflight(t, e, "leftover")
	want = readFixture(t, "certs/leftover/inflight")
	missingFields(t, "certs/leftover/inflight", want, got)
	missingFields(t, "certs/leftover/inflight published 0", want["published"].([]any)[0].(map[string]any), got["published"].([]any)[0].(map[string]any))
}

func TestWritesStorageV1Fields(t *testing.T) {
	h := newHarness(t)
	h.imp("example.com", testcerts.New(t, testcerts.Options{}))

	for _, key := range []string{"certs/example.com/meta", "certs/example.com/versions/1"} {
		fixtureKey := key
		if strings.HasSuffix(key, "/versions/1") {
			fixtureKey = "certs/example.com/versions/2"
		}
		want := readFixture(t, fixtureKey)

		entry, err := h.storage.Get(context.Background(), key)
		if err != nil || entry == nil {
			t.Fatalf("%s: %v", key, err)
		}
		var got map[string]any
		if err := json.Unmarshal(entry.Value, &got); err != nil {
			t.Fatal(err)
		}
		missingFields(t, key, want, got)
	}
}

// missingFields reports fields of the fixture that a fresh write no longer
// produces: a rename or removal that would strand data written by v1.
func missingFields(t *testing.T, at string, want, got map[string]any) {
	t.Helper()
	for field, wantValue := range want {
		gotValue, ok := got[field]
		if !ok {
			t.Errorf("%s: field %q is no longer written", at, field)
			continue
		}
		if w, ok := wantValue.(map[string]any); ok {
			if g, ok := gotValue.(map[string]any); ok {
				missingFields(t, at+"."+field, w, g)
			}
		}
	}
}
