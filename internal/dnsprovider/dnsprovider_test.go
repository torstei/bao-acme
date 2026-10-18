// SPDX-License-Identifier: MPL-2.0

package dnsprovider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-acme/lego/v5/challenge/dns01"

	"github.com/torstei/bao-acme/internal/acmetest"
)

const (
	zone       = "example.test"
	domain     = "www.example.test"
	keyAuth    = "token.thumbprint"
	tsigName   = "bao-acme."
	tsigSecret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
)

// useResolver points lego's process-wide DNS client at addr for the test.
func useResolver(t *testing.T, addr string) {
	t.Helper()
	prev := dns01.DefaultClient()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: []string{addr}}))
	t.Cleanup(func() { dns01.SetDefaultClient(prev) })
}

func challengeValue(t *testing.T) (name, value string) {
	t.Helper()
	info := dns01.GetChallengeInfo(context.Background(), domain, keyAuth)
	return info.EffectiveFQDN, info.Value
}

func build(t *testing.T, provider string, s Settings, hc *http.Client) (interface {
	Present(context.Context, string, string, string) error
	CleanUp(context.Context, string, string, string) error
}, error) {
	t.Helper()
	spec, ok := Lookup(provider)
	if !ok {
		t.Fatalf("no provider %s", provider)
	}
	return spec.Build(s, Common{}, hc)
}

func TestDomeneshop(t *testing.T) {
	d := acmetest.StartDNS(t, nil, zone)
	useResolver(t, d.Addr)
	fake := acmetest.StartDomeneshop(t, d, zone, "tok", "sec")
	ctx := context.Background()

	p, err := build(t, "domeneshop", Settings{"api_token": "tok", "api_secret": "sec"}, fake.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present(ctx, domain, "", keyAuth); err != nil {
		t.Fatal(err)
	}
	name, value := challengeValue(t)
	if got := d.TXT(name); len(got) != 1 || got[0] != value {
		t.Fatalf("TXT %s = %v, want [%s]", name, got, value)
	}
	if got := fake.Records(); len(got) != 1 || got[0] != "_acme-challenge.www="+value {
		t.Errorf("API records = %v", got)
	}

	if err := p.CleanUp(ctx, domain, "", keyAuth); err != nil {
		t.Fatal(err)
	}
	if got := d.TXT(name); len(got) != 0 {
		t.Errorf("TXT after clean-up = %v", got)
	}

	wrong, err := build(t, "domeneshop", Settings{"api_token": "tok", "api_secret": "wrong"}, fake.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Present(ctx, domain, "", keyAuth); err == nil {
		t.Error("presented with a wrong secret")
	}
}

func TestDNSUpdate(t *testing.T) {
	d := acmetest.StartDNS(t, &acmetest.TSIG{Name: tsigName, Secret: tsigSecret}, zone)
	useResolver(t, d.Addr)
	ctx := context.Background()
	settings := Settings{"nameserver": d.Addr, "tsig_key": tsigName, "tsig_secret": tsigSecret}

	p, err := build(t, "dnsupdate", settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present(ctx, domain, "", keyAuth); err != nil {
		t.Fatal(err)
	}
	name, value := challengeValue(t)
	if got := d.TXT(name); len(got) != 1 || got[0] != value {
		t.Fatalf("TXT %s = %v, want [%s]", name, got, value)
	}
	if err := p.CleanUp(ctx, domain, "", keyAuth); err != nil {
		t.Fatal(err)
	}
	if got := d.TXT(name); len(got) != 0 {
		t.Errorf("TXT after clean-up = %v", got)
	}

	settings["tsig_secret"] = "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="
	wrong, err := build(t, "dnsupdate", settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Present(ctx, domain, "", keyAuth); err == nil {
		t.Error("updated with a wrong TSIG secret")
	}
	if got := d.TXT(name); len(got) != 0 {
		t.Errorf("TXT after a refused update = %v", got)
	}
}

type recordingTransport struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Host)
	r.mu.Unlock()
	return nil, errors.New("blocked by test")
}

func TestCloudflareUsesTheGivenHTTPClient(t *testing.T) {
	d := acmetest.StartDNS(t, nil, zone)
	useResolver(t, d.Addr)
	rt := &recordingTransport{}

	p, err := build(t, "cloudflare", Settings{"api_token": "tok"}, &http.Client{Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present(context.Background(), domain, "", keyAuth); err == nil {
		t.Fatal("present succeeded through a blocked client")
	}
	if len(rt.hosts) == 0 {
		t.Fatal("the provider did not use the given HTTP client")
	}
	for _, h := range rt.hosts {
		if h != "api.cloudflare.com" {
			t.Errorf("request to %s", h)
		}
	}
}

func TestBuildValidates(t *testing.T) {
	cases := []struct {
		provider string
		settings Settings
		common   Common
		want     string
	}{
		{"domeneshop", Settings{"api_token": "t"}, Common{}, "needs api_secret"},
		{"domeneshop", Settings{"api_token": "t", "api_secret": "s", "nameserver": "x"}, Common{}, `no setting "nameserver"`},
		{"cloudflare", Settings{}, Common{}, "needs api_token"},
		{"cloudflare", Settings{"api_token": "t", "api_key": "k", "email": "e"}, Common{}, "not both"},
		{"cloudflare", Settings{"api_key": "k"}, Common{}, "set together"},
		{"cloudflare", Settings{"email": "e", "api_key": "k", "zone_api_token": "z"}, Common{}, "zone_api_token needs api_token"},
		{"dnsupdate", Settings{}, Common{}, "needs nameserver"},
		{"dnsupdate", Settings{"nameserver": "ns", "tsig_key": "k"}, Common{}, "set together"},
		{"dnsupdate", Settings{"nameserver": "ns", "tsig_algorithm": "hmac-md5"}, Common{}, "tsig_algorithm must be"},
		{"domeneshop", Settings{"api_token": "t", "api_secret": "s"}, Common{TTL: -1}, "cannot be negative"},
	}
	for _, c := range cases {
		spec, _ := Lookup(c.provider)
		_, err := spec.Build(c.settings, c.common, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: err = %v, want %q", c.provider, c.settings, err, c.want)
		}
	}
}

func TestAllFieldsNamesEveryProvider(t *testing.T) {
	f := AllFields()["api_token"]
	if !f.Secret || !strings.Contains(f.Description, "cloudflare:") || !strings.Contains(f.Description, "domeneshop:") {
		t.Errorf("api_token = %+v", f)
	}
	if got := strings.Join(Names(), ","); got != "cloudflare,dnsupdate,domeneshop" {
		t.Errorf("Names = %s", got)
	}
}
