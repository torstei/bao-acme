// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torstei/bao-acme/internal/acmetest"
	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/dnsprovider"
)

const (
	testZone   = "example.test"
	tsigName   = "bao-acme."
	tsigSecret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
)

type issuanceEnv struct {
	dns     *acmetest.DNS
	pebble  *acmetest.Pebble
	account *Account
}

func newIssuanceEnv(t *testing.T) *issuanceEnv {
	t.Helper()
	return newIssuanceEnvWith(t, acmetest.Options{})
}

func newIssuanceEnvWith(t *testing.T, opts acmetest.Options) *issuanceEnv {
	t.Helper()
	d := acmetest.StartDNS(t, &acmetest.TSIG{Name: tsigName, Secret: tsigSecret}, testZone)
	opts.Resolver = d.Addr
	p := acmetest.Start(t, opts)
	a := newAccount(t, p)
	reg, _, err := Register(context.Background(), a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.AccountURL = reg.AccountURL
	a.Network = &Network{DNS: DNSSettings{
		Resolvers:        []string{d.Addr},
		PropagationCheck: PropagationResolvers,
	}}
	return &issuanceEnv{dns: d, pebble: p, account: a}
}

func (e *issuanceEnv) provider(t *testing.T) *dnsprovider.Spec {
	t.Helper()
	spec, _ := dnsprovider.Lookup("dnsupdate")
	return spec
}

func (e *issuanceEnv) obtain(t *testing.T, names []string, keyType string) ([]byte, error) {
	t.Helper()
	p, err := e.provider(t).Build(dnsprovider.Settings{
		"nameserver": e.dns.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret,
	}, dnsprovider.Common{PropagationTimeout: 10 * time.Second, PollingInterval: 100 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cert.GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := Obtain(context.Background(), e.account, p, Order{Names: names, Key: key})
	if err != nil {
		return nil, err
	}
	keyPEM, _ := cert.EncodeKey(key)
	if _, err := cert.Parse(string(chain), keyPEM, time.Now()); err != nil {
		t.Fatalf("issued chain does not validate with its key: %v", err)
	}
	return chain, nil
}

func TestObtain(t *testing.T) {
	e := newIssuanceEnv(t)
	names := []string{"*.example.test", "example.test"}

	chain, err := e.obtain(t, names, "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := cert.ParseCertificates(string(chain))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) < 2 {
		t.Errorf("chain has %d certificates, want the leaf and its issuer", len(certs))
	}
	if got := strings.Join(cert.Names(certs[0]), ","); got != "*.example.test,example.test" {
		t.Errorf("names = %s", got)
	}
	if got := e.dns.TXT("_acme-challenge.example.test"); len(got) != 0 {
		t.Errorf("challenge records left behind: %v", got)
	}
}

func TestObtainRSA(t *testing.T) {
	e := newIssuanceEnv(t)
	if _, err := e.obtain(t, []string{"rsa.example.test"}, "rsa-2048"); err != nil {
		t.Fatal(err)
	}
}

func TestObtainFailsWhenTheRecordCannotBePublished(t *testing.T) {
	e := newIssuanceEnv(t)
	if _, err := e.obtain(t, []string{"elsewhere.invalid"}, "ecdsa-p256"); err == nil {
		t.Fatal("obtained a certificate for a zone the DNS server does not serve")
	}
}

func TestObtainRefusesWithoutResolvers(t *testing.T) {
	e := newIssuanceEnv(t)
	e.account.Network.DNS.Resolvers = nil
	prev := resolvConf
	resolvConf = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { resolvConf = prev })

	if _, err := e.obtain(t, []string{"example.test"}, "ecdsa-p256"); !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("err = %v, want ErrNoResolvers", err)
	}
}

func TestObtainNeedsARegisteredAccount(t *testing.T) {
	e := newIssuanceEnv(t)
	e.account.AccountURL = ""
	if _, err := e.obtain(t, []string{"example.test"}, "ecdsa-p256"); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("err = %v", err)
	}
}

func leafOf(t *testing.T, chain []byte) *x509.Certificate {
	t.Helper()
	certs, err := cert.ParseCertificates(string(chain))
	if err != nil {
		t.Fatal(err)
	}
	return certs[0]
}

func TestRenewalInfoAndReplaces(t *testing.T) {
	e := newIssuanceEnv(t)
	ctx := context.Background()
	chain, err := e.obtain(t, []string{"www.example.test"}, "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, chain)

	w, err := GetRenewalInfo(ctx, e.account, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Start.After(leaf.NotBefore) || !w.End.Before(leaf.NotAfter.Add(time.Second)) || !w.Start.Before(w.End) {
		t.Errorf("window %v – %v for a certificate valid %v – %v", w.Start, w.End, leaf.NotBefore, leaf.NotAfter)
	}
	if w.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v", w.RetryAfter)
	}

	renew := func() error {
		p, err := e.provider(t).Build(dnsprovider.Settings{
			"nameserver": e.dns.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret,
		}, dnsprovider.Common{PropagationTimeout: 10 * time.Second, PollingInterval: 100 * time.Millisecond}, nil)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := cert.GenerateKey("ecdsa-p256")
		_, err = Obtain(ctx, e.account, p, Order{Names: []string{"www.example.test"}, Key: key, Replaces: leaf})
		return err
	}
	if err := renew(); err != nil {
		t.Fatalf("renewal replacing the certificate: %v", err)
	}
	// The CA answers alreadyReplaced, and lego orders again without it.
	if err := renew(); err != nil {
		t.Errorf("replacing an already replaced certificate: %v", err)
	}
}

// TestRefusedReplacesIsOrderedAgainWithout: replaces is optional, so a CA
// refusing an order for it must not cost the renewal, unless the refusal is
// a rate limit, which replaces may be what exempts the order from.
func TestRefusedReplacesIsOrderedAgainWithout(t *testing.T) {
	for _, c := range []struct {
		problem string
		retried bool
	}{
		{"urn:ietf:params:acme:error:serverInternal", true},
		{"urn:ietf:params:acme:error:malformed", true},
		{"urn:ietf:params:acme:error:rateLimited", false},
	} {
		t.Run(c.problem, func(t *testing.T) {
			e := newIssuanceEnvWith(t, acmetest.Options{RefuseReplaces: c.problem})
			chain, err := e.obtain(t, []string{"www.example.test"}, "ecdsa-p256")
			if err != nil {
				t.Fatal(err)
			}
			p, err := e.provider(t).Build(dnsprovider.Settings{
				"nameserver": e.dns.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret,
			}, dnsprovider.Common{PropagationTimeout: 10 * time.Second, PollingInterval: 100 * time.Millisecond}, nil)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := cert.GenerateKey("ecdsa-p256")
			var refused error
			_, err = Obtain(context.Background(), e.account, p, Order{
				Names: []string{"www.example.test"}, Key: key, Replaces: leafOf(t, chain),
				OnReplacesRefused: func(err error) { refused = err },
			})

			if n := e.pebble.RefusedReplaces(); n != 1 {
				t.Fatalf("orders refused for replaces = %d, want 1", n)
			}
			switch {
			case c.retried && (err != nil || refused == nil || e.pebble.OrdersPlaced() != 2):
				t.Errorf("renewal = %v, refusal reported %v, orders %d; want it ordered again without replaces", err, refused, e.pebble.OrdersPlaced())
			case !c.retried && (err == nil || refused != nil || e.pebble.OrdersPlaced() != 1):
				t.Errorf("renewal = %v, refusal reported %v, orders %d; want no second order", err, refused, e.pebble.OrdersPlaced())
			}
		})
	}
}

// TestFailureAfterOrderingKeepsReplaces: only a refused order is placed
// again; a failure once the order exists, here the CA failing to validate a
// record that was never published, is not. The CA reuses www's
// authorization, so the new name is what fails.
func TestFailureAfterOrderingKeepsReplaces(t *testing.T) {
	e := newIssuanceEnv(t)
	chain, err := e.obtain(t, []string{"www.example.test"}, "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	e.account.Network.DNS.PropagationCheck = PropagationNone
	key, _ := cert.GenerateKey("ecdsa-p256")
	refused := false
	_, err = Obtain(context.Background(), e.account, publishesNothing{}, Order{
		Names: []string{"www.example.test", "new.example.test"}, Key: key, Replaces: leafOf(t, chain),
		OnReplacesRefused: func(error) { refused = true },
	})
	if err == nil || refused || e.pebble.OrdersPlaced() != 2 {
		t.Errorf("renewal = %v, refusal reported %v, orders %d; want one failed order", err, refused, e.pebble.OrdersPlaced())
	}
}

type publishesNothing struct{}

func (publishesNothing) Present(context.Context, string, string, string) error { return nil }
func (publishesNothing) CleanUp(context.Context, string, string, string) error { return nil }

func TestRevokedCertificateIsDueAtOnce(t *testing.T) {
	e := newIssuanceEnv(t)
	ctx := context.Background()
	chain, err := e.obtain(t, []string{"www.example.test"}, "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, e.account, chain); err != nil {
		t.Fatal(err)
	}
	w, err := GetRenewalInfo(ctx, e.account, leafOf(t, chain))
	if err != nil {
		t.Fatal(err)
	}
	if w.Start.After(time.Now().Add(time.Minute)) {
		t.Errorf("window after revocation starts %v, want now", w.Start)
	}
}

func TestOrderURLIsReportedAndRecoverable(t *testing.T) {
	e := newIssuanceEnv(t)
	ctx := context.Background()
	p, err := e.provider(t).Build(dnsprovider.Settings{
		"nameserver": e.dns.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret,
	}, dnsprovider.Common{PropagationTimeout: 10 * time.Second, PollingInterval: 100 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := cert.GenerateKey("ecdsa-p256")

	var orderURLs []string
	chain, err := Obtain(ctx, e.account, p, Order{
		Names:          []string{"www.example.test"},
		Key:            key,
		OnOrderCreated: func(u string) { orderURLs = append(orderURLs, u) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(orderURLs) != 1 || !strings.HasPrefix(orderURLs[0], "https://") {
		t.Fatalf("order URLs = %v", orderURLs)
	}

	state, err := FetchOrder(ctx, e.account, orderURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "valid" || string(state.Chain) != string(chain) {
		t.Errorf("fetched order: status %s, same chain %v", state.Status, string(state.Chain) == string(chain))
	}
	keyPEM, _ := cert.EncodeKey(key)
	if _, err := cert.Parse(string(state.Chain), keyPEM, time.Now()); err != nil {
		t.Errorf("recovered chain does not go with the key: %v", err)
	}

	if _, err := FetchOrder(ctx, e.account, orderURLs[0]+"-nope"); err == nil {
		t.Error("fetched an order that does not exist")
	}
}
