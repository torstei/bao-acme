// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

const testKeyAuth = "token.thumbprint"

// defineQuietly stores a definition without starting an issuance, as if the
// engine had stopped right after it was written.
func (e *managedEnv) defineQuietly(name string, names ...string) *managedSpec {
	e.t.Helper()
	spec := &managedSpec{Names: names, KeyType: "ecdsa-p256", Account: "le", DNS: "bind", DefinedTime: time.Now().UTC()}
	m, _ := loadMeta(context.Background(), e.storage, name)
	if m == nil {
		m = &certMeta{MaxVersions: defaultMaxVersions}
	}
	m.Managed = spec
	if err := putJSON(context.Background(), e.storage, metaKey(name), m); err != nil {
		e.t.Fatal(err)
	}
	return spec
}

func (e *managedEnv) inflight(name string) *inflightEntry {
	e.t.Helper()
	i, err := loadInflight(context.Background(), e.storage, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return i
}

// obtainBehindTheEnginesBack has the CA issue a certificate for spec, as an
// attempt would have before the engine stopped, and returns the chain, the
// key and the order URL.
func (e *managedEnv) obtainBehindTheEnginesBack(name string, spec *managedSpec) ([]byte, string, string) {
	e.t.Helper()
	ctx := context.Background()
	n, _ := loadNetwork(ctx, e.storage)
	network, _ := n.network()
	account, err := e.b.registeredAccount(ctx, e.storage, spec.Account, network)
	if err != nil {
		e.t.Fatal(err)
	}
	dnsEntry, _ := loadDNS(ctx, e.storage, spec.DNS)
	provider, err := dnsEntry.provider(n)
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := cert.GenerateKey(spec.KeyType)
	keyPEM, _ := cert.EncodeKey(key)
	var orderURL string
	chain, err := acmeclient.Obtain(ctx, account, provider, acmeclient.Order{
		Names: spec.Names, Key: key, OnOrderCreated: func(u string) { orderURL = u },
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return chain, keyPEM, orderURL
}

func TestNoInflightLeftAfterAttempts(t *testing.T) {
	e := newManagedEnv(t)
	e.define("ok", "ok.example.test")
	e.waitFor("ok", "the certificate", hasVersion(1))

	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.define("bad", "bad.example.test")
	e.waitFor("bad", "a failure", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures == 1 })

	time.Sleep(100 * time.Millisecond)
	for _, name := range []string{"ok", "bad"} {
		if i := e.inflight(name); i != nil {
			t.Errorf("%s: in-flight entry left after the attempt: %+v", name, i)
		}
	}
}

func TestRecoversACertificateTheCAIssued(t *testing.T) {
	e := newManagedEnv(t)
	spec := e.defineQuietly("www", "www.example.test")
	chain, keyPEM, orderURL := e.obtainBehindTheEnginesBack("www", spec)
	if orderURL == "" {
		t.Fatal("no order URL")
	}
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Reason: "no certificate yet",
		Account: "le", DNS: "bind", Privkey: keyPEM, OrderURL: orderURL,
	}); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	e.waitFor("www", "the recovered certificate", hasVersion(1))

	got := e.current("www")
	if !strings.HasPrefix(got.Certificate, strings.SplitAfter(string(chain), "-----END CERTIFICATE-----\n")[0]) {
		t.Error("stored a different certificate than the CA issued: a new order was placed")
	}
	if got.Privkey != keyPEM {
		t.Error("stored a different key than the interrupted attempt's")
	}
	m, _ := loadMeta(context.Background(), e.storage, "www")
	if a := m.Issuance.Attempts; len(a) == 0 || !strings.HasPrefix(a[0].Reason, "recovered after an interruption") {
		t.Errorf("attempts = %+v", a)
	}
	if i := e.inflight("www"); i != nil {
		t.Errorf("in-flight entry kept after recovery: %+v", i)
	}
}

func TestCleansUpLeftoverRecords(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("www", testcerts.New(t, testcerts.Options{Names: []string{"www.example.test"}}))
	spec := e.defineQuietly("www", "www.example.test")

	dnsEntry, _ := loadDNS(context.Background(), e.storage, "bind")
	provider, _ := dnsEntry.provider(&networkEntry{})
	if err := provider.Present(context.Background(), "www.example.test", "tok", testKeyAuth); err != nil {
		t.Fatal(err)
	}
	e.dns.SetTXT("_acme-challenge.www.example.test", "someone else's")
	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 2 {
		t.Fatalf("setup: TXT = %v", got)
	}
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Account: "le", DNS: "bind",
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", KeyAuth: testKeyAuth, PublishedTime: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	deadline := time.Now().Add(10 * time.Second)
	for e.inflight("www") != nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if i := e.inflight("www"); i != nil {
		t.Fatalf("in-flight entry kept: %+v", i)
	}
	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 1 || got[0] != "someone else's" {
		t.Errorf("TXT after clean-up = %v, want only someone else's", got)
	}
	if m, _ := loadMeta(context.Background(), e.storage, "www"); m.CurrentVersion != 1 {
		t.Error("cleaning up issued a certificate that was not due")
	}
}

// TestLeftoverAlreadyGoneIsDropped: a record the provider no longer has is
// done with, even though removing it would now fail.
func TestLeftoverAlreadyGoneIsDropped(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("www", testcerts.New(t, testcerts.Options{Names: []string{"www.example.test"}}))
	spec := e.defineQuietly("www", "www.example.test")
	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.dns.SetTXT("_acme-challenge.www.example.test", "someone else's")
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Account: "le", DNS: "bind",
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", KeyAuth: testKeyAuth, PublishedTime: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	deadline := time.Now().Add(10 * time.Second)
	for e.inflight("www") != nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if i := e.inflight("www"); i != nil {
		t.Fatalf("in-flight entry kept: %+v", i)
	}
	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 1 {
		t.Errorf("TXT = %v", got)
	}
}

func TestLeftoverThatCannotBeRemovedIsKeptAndShown(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("www", testcerts.New(t, testcerts.Options{Names: []string{"www.example.test"}}))
	spec := e.defineQuietly("www", "www.example.test")
	dnsEntry, _ := loadDNS(context.Background(), e.storage, "bind")
	provider, _ := dnsEntry.provider(&networkEntry{})
	if err := provider.Present(context.Background(), "www.example.test", "tok", testKeyAuth); err != nil {
		t.Fatal(err)
	}
	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Account: "le", DNS: "bind",
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", KeyAuth: testKeyAuth, PublishedTime: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if i := e.inflight("www"); i != nil && !i.NextCleanupTime.IsZero() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	i := e.inflight("www")
	if i == nil || len(i.Published) != 1 || i.Published[0].CleanupError == "" || i.NextCleanupTime.Sub(time.Now()) < cleanupRetry-time.Minute || i.NextCleanupTime.Sub(time.Now()) > cleanupRetry {
		t.Fatalf("in-flight entry = %+v", i)
	}

	s := e.ok(logical.ReadOperation, "certs/www/status", nil)
	inflight := s.Data["inflight"].(map[string]any)
	published := inflight["published"].([]map[string]any)
	if len(published) != 1 || published[0]["cleanup_error"] == "" {
		t.Errorf("status inflight = %v", inflight)
	}
	if _, ok := inflight["privkey"]; ok {
		t.Error("status shows the in-flight key")
	}

	e.periodic()
	time.Sleep(200 * time.Millisecond)
	if again := e.inflight("www"); !again.NextCleanupTime.Equal(i.NextCleanupTime) {
		t.Error("retried the clean-up before it was due")
	}
}

func TestUnrecoverableOrderIsDropped(t *testing.T) {
	e := newManagedEnv(t)
	spec := e.defineQuietly("www", "www.example.test")
	key, _ := cert.GenerateKey("ecdsa-p256")
	keyPEM, _ := cert.EncodeKey(key)
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Account: "le", DNS: "bind",
		Privkey: keyPEM, OrderURL: "https://127.0.0.1:1/order/gone",
	}); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	e.waitFor("www", "a fresh certificate", hasVersion(1))
	if e.current("www").Privkey == keyPEM {
		t.Error("used the dropped attempt's key")
	}
	if i := e.inflight("www"); i != nil {
		t.Errorf("in-flight entry kept: %+v", i)
	}
}

func TestCleanupDelay(t *testing.T) {
	now := time.Now()
	recent := publishedRecord{PublishedTime: now.Add(-10 * time.Minute)}
	old := publishedRecord{PublishedTime: now.Add(-2 * time.Hour)}
	if got := cleanupDelay([]publishedRecord{old, recent}, now); got != cleanupRetry {
		t.Errorf("with a recent record: %v", got)
	}
	if got := cleanupDelay([]publishedRecord{old}, now); got != cleanupRetrySlow {
		t.Errorf("with only old records: %v", got)
	}
}

func TestSettleRecord(t *testing.T) {
	recs := func() []publishedRecord {
		return []publishedRecord{{Domain: "a", Token: "1"}, {Domain: "b", Token: "2", PresentError: "refused"}}
	}
	if got := settleRecord(recs(), "a", "1", nil); len(got) != 1 || got[0].Domain != "b" {
		t.Errorf("removed record kept: %+v", got)
	}
	if got := settleRecord(recs(), "a", "1", errFake); len(got) != 2 || got[0].CleanupError == "" {
		t.Errorf("a record that could not be removed: %+v", got)
	}
	if got := settleRecord(recs(), "b", "2", errFake); len(got) != 1 || got[0].Domain != "a" {
		t.Errorf("a record that was never published was kept: %+v", got)
	}
}

var errFake = fakeError("refused")

type fakeError string

func (e fakeError) Error() string { return string(e) }
