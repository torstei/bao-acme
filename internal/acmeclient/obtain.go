// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

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

// Obtain orders a certificate for names over DNS-01, publishing challenge
// records through provider, and returns the PEM certificate chain, leaf
// first. The account must be registered.
func Obtain(ctx context.Context, a *Account, provider challenge.Provider, names []string, key crypto.Signer) ([]byte, error) {
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

	client, _, err := newClient(a)
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

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains:    names,
		PrivateKey: key,
		Bundle:     true,
	})
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
