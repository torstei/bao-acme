// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
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
	d := acmetest.StartDNS(t, &acmetest.TSIG{Name: tsigName, Secret: tsigSecret}, testZone)
	p := acmetest.Start(t, acmetest.Options{Resolver: d.Addr})
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
	chain, err := Obtain(context.Background(), e.account, p, names, key)
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
