// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
)

// ErrNoResolvers means DNS-01 has no resolvers to use. lego would fall back
// to public resolvers; the engine refuses instead.
var ErrNoResolvers = errors.New("no DNS resolvers: set dns_resolvers in config/network, or give this node an /etc/resolv.conf")

// lego's DNS client is process-wide, so issuances that set it run one at a
// time.
var dnsMu sync.Mutex

// ErrNoARI means the CA does not offer renewal information (RFC 9773).
var ErrNoARI = api.ErrNoARI

// ErrNoRenewalInfoForCert means the CA refused renewal information for this
// certificate, typically because another CA issued it. Asking again soon
// will not help.
var ErrNoRenewalInfoForCert = errors.New("the CA has no renewal information for this certificate")

// Order is what to obtain.
type Order struct {
	Names []string
	Key   crypto.Signer
	// Replaces, when set, is the certificate this order renews, so the CA
	// can link them (RFC 9773). It must be one this account was issued.
	Replaces *x509.Certificate
	// OnOrderCreated, when set, is called with the order's URL as soon as
	// the CA has created it, so the order can be found again after a
	// restart.
	OnOrderCreated func(orderURL string)
}

// Obtain orders a certificate over DNS-01, publishing challenge records
// through provider, and returns the PEM certificate chain, leaf first. The
// account must be registered.
func Obtain(ctx context.Context, a *Account, provider challenge.Provider, order Order) ([]byte, error) {
	if a.AccountURL == "" {
		return nil, errors.New("the account is not registered")
	}
	settings := DNSSettings{PropagationCheck: PropagationAuthoritative}
	if a.Network != nil {
		settings = a.Network.DNS
	}
	resolvers := settings.EffectiveResolvers()
	if len(resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	var wraps []func(http.RoundTripper) http.RoundTripper
	if order.OnOrderCreated != nil {
		newOrderURL, err := newOrderURL(a)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, func(next http.RoundTripper) http.RoundTripper {
			return &orderObserver{next: next, newOrderURL: newOrderURL, created: order.OnOrderCreated}
		})
	}
	client, _, err := newClient(a, wraps...)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider, propagationOptions(settings)); err != nil {
		return nil, err
	}

	dnsMu.Lock()
	defer dnsMu.Unlock()
	prev := dns01.DefaultClient()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{
		RecursiveNameservers: resolvers,
		TCPOnly:              settings.TCPOnly,
	}))
	defer dns01.SetDefaultClient(prev)

	req := certificate.ObtainRequest{
		Domains:    order.Names,
		PrivateKey: order.Key,
		Bundle:     true,
	}
	if order.Replaces != nil {
		if req.ReplacesCertID, err = api.MakeARICertID(order.Replaces); err != nil {
			return nil, err
		}
	}
	res, err := client.Certificate.Obtain(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("obtaining a certificate: %w", err)
	}
	return res.Certificate, nil
}

func propagationOptions(d DNSSettings) dns01.ChallengeOption {
	var opts []dns01.ChallengeOption
	switch d.PropagationCheck {
	case PropagationResolvers:
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	case PropagationNone:
		return dns01.PropagationWait(d.PropagationDelay, true)
	default:
		opts = append(opts, dns01.DisableRecursiveNSsPropagationRequirement())
	}
	if d.PropagationDelay > 0 {
		opts = append(opts, dns01.PropagationWait(d.PropagationDelay, false))
	}
	return dns01.CombineOptions(opts...)
}

// RenewalWindow is the CA's suggestion for when to renew a certificate.
type RenewalWindow struct {
	Start, End     time.Time
	ExplanationURL string
	// RetryAfter is when the CA suggests asking again; zero if it gave none.
	RetryAfter time.Duration
}

// GetRenewalInfo asks the CA when to renew leaf. It returns ErrNoARI if the
// CA does not offer renewal information. The account need not be
// registered.
func GetRenewalInfo(ctx context.Context, a *Account, leaf *x509.Certificate) (*RenewalWindow, error) {
	client, _, err := newClient(a)
	if err != nil {
		return nil, err
	}
	info, err := client.Certificate.GetRenewalInfo(ctx, leaf)
	if err != nil {
		var problem *acme.ProblemDetails
		if errors.As(err, &problem) && problem.HTTPStatus >= 400 && problem.HTTPStatus < 500 {
			return nil, fmt.Errorf("%w: %v", ErrNoRenewalInfoForCert, err)
		}
		return nil, err
	}
	return &RenewalWindow{
		Start:          info.SuggestedWindow.Start.UTC(),
		End:            info.SuggestedWindow.End.UTC(),
		ExplanationURL: info.ExplanationURL,
		RetryAfter:     info.RetryAfter,
	}, nil
}

// Revoke revokes a certificate this account was issued.
func Revoke(ctx context.Context, a *Account, certPEM []byte) error {
	client, _, err := newClient(a)
	if err != nil {
		return err
	}
	return client.Certificate.Revoke(ctx, certPEM)
}

func newOrderURL(a *Account) (string, error) {
	core, err := api.New(a.Network.HTTPClient(a.CABundle), userAgent, a.DirectoryURL, a.AccountURL, a.Key)
	if err != nil {
		return "", fmt.Errorf("ACME directory %s: %w", a.DirectoryURL, err)
	}
	return core.GetDirectory().NewOrderURL, nil
}

// orderObserver reports the Location of a successful newOrder request.
type orderObserver struct {
	next        http.RoundTripper
	newOrderURL string
	created     func(string)
}

func (o *orderObserver) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := o.next.RoundTrip(req)
	if err == nil && req.Method == http.MethodPost && req.URL.String() == o.newOrderURL && resp.StatusCode == http.StatusCreated {
		if loc := resp.Header.Get("Location"); loc != "" {
			o.created(loc)
		}
	}
	return resp, err
}

// OrderState is what the CA says about an existing order.
type OrderState struct {
	Status string
	// Chain is the issued certificate chain, leaf first, once the order is
	// valid.
	Chain []byte
}

// FetchOrder reads an order this account created and, once it is valid,
// downloads its certificate.
func FetchOrder(ctx context.Context, a *Account, orderURL string) (*OrderState, error) {
	core, err := api.New(a.Network.HTTPClient(a.CABundle), userAgent, a.DirectoryURL, a.AccountURL, a.Key)
	if err != nil {
		return nil, fmt.Errorf("ACME directory %s: %w", a.DirectoryURL, err)
	}
	order, err := core.Orders.Get(ctx, orderURL)
	if err != nil {
		return nil, fmt.Errorf("reading order %s: %w", orderURL, err)
	}
	state := &OrderState{Status: order.Status}
	if order.Status == acme.StatusValid && order.Certificate != "" {
		raw, err := core.Certificates.Get(ctx, order.Certificate, true)
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", order.Certificate, err)
		}
		state.Chain = raw.Cert
	}
	return state, nil
}
