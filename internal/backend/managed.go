// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
)

const (
	defaultCertKeyType = "ecdsa-p256"
	issuanceTimeout    = 15 * time.Minute
	firstBackoff       = time.Minute
	maxBackoff         = 6 * time.Hour
	maxErrorLength     = 2000
)

// managedSpec defines a certificate the engine obtains itself.
type managedSpec struct {
	Names       []string  `json:"names"`
	KeyType     string    `json:"key_type"`
	Account     string    `json:"account"`
	DNSProvider string    `json:"dns_provider"`
	DefinedTime time.Time `json:"defined_time"`
}

// issuanceState is the outcome of the engine's attempts so far.
type issuanceState struct {
	LastAttemptTime time.Time `json:"last_attempt_time,omitzero"`
	LastSuccessTime time.Time `json:"last_success_time,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
	Failures        int       `json:"failures,omitempty"`
	NextAttemptTime time.Time `json:"next_attempt_time,omitzero"`
}

func (s *managedSpec) source() string {
	return "acme:" + s.Account
}

// matches reports whether v is what spec asks for.
func (s *managedSpec) matches(v *certVersion) bool {
	return v != nil && slices.Equal(v.Description.Names, s.Names) && v.Description.KeyType == s.KeyType
}

// needsIssuance says why the engine should obtain a certificate now, or ""
// when it should not.
func needsIssuance(m *certMeta, current *certVersion, now time.Time) string {
	if m == nil || m.Managed == nil {
		return ""
	}
	if m.Issuance != nil && now.Before(m.Issuance.NextAttemptTime) {
		return ""
	}
	switch {
	case current == nil:
		return "no certificate yet"
	case current.destroyed():
		return "the current key was destroyed"
	case !now.Before(current.Description.NotAfter):
		return "the current certificate has expired"
	case !m.Managed.matches(current):
		return "the current certificate does not match the definition"
	}
	return ""
}

func backoff(failures int) time.Duration {
	d := firstBackoff
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	d = min(d, maxBackoff)
	return d - d/10 + rand.N(d/5+1)
}

// issuer runs issuances in the background, at most one per certificate.
type issuer struct {
	mu      sync.Mutex
	running map[string]bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newIssuer() *issuer {
	ctx, cancel := context.WithCancel(context.Background())
	return &issuer{running: map[string]bool{}, ctx: ctx, cancel: cancel}
}

// start runs fn for name unless it is already running.
func (i *issuer) start(name string, fn func(context.Context)) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.running[name] || i.ctx.Err() != nil {
		return false
	}
	i.running[name] = true
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		defer func() {
			i.mu.Lock()
			delete(i.running, name)
			i.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(i.ctx, issuanceTimeout)
		defer cancel()
		fn(ctx)
	}()
	return true
}

func (i *issuer) stop() {
	i.cancel()
	i.wg.Wait()
}

// startIssuance obtains a certificate for name in the background, if it
// needs one.
func (b *backend) startIssuance(name string) bool {
	return b.issuer.start(name, func(ctx context.Context) {
		if err := b.issue(ctx, b.storage, name); err != nil {
			b.Logger().Error("issuance failed", "certificate", name, "error", err)
		}
	})
}

// periodic starts the issuances that are due. It runs on the active node.
func (b *backend) periodic(ctx context.Context, req *logical.Request) error {
	names, err := listNames(ctx, req.Storage)
	if err != nil {
		return err
	}
	now := b.now()
	for _, name := range names {
		m, err := loadMeta(ctx, req.Storage, name)
		if err != nil || m == nil || m.Managed == nil {
			continue
		}
		current, err := loadVersion(ctx, req.Storage, name, m.CurrentVersion)
		if err != nil {
			continue
		}
		if needsIssuance(m, current, now) != "" {
			b.startIssuance(name)
		}
	}
	return nil
}

// issue obtains and stores a certificate for name if it needs one. Failures
// are recorded in the certificate's issuance state with a backoff.
func (b *backend) issue(ctx context.Context, s logical.Storage, name string) error {
	spec, reason, err := b.claimIssuance(ctx, s, name)
	if err != nil || spec == nil {
		return err
	}
	b.Logger().Info("obtaining a certificate", "certificate", name, "reason", reason, "names", spec.Names)

	bundle, issueErr := b.obtain(ctx, s, spec)
	return b.recordIssuance(ctx, s, name, spec, bundle, issueErr)
}

// claimIssuance records the start of an attempt and returns the definition,
// or nil if nothing needs doing.
func (b *backend) claimIssuance(ctx context.Context, s logical.Storage, name string) (*managedSpec, string, error) {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, s, name)
	if err != nil || m == nil {
		return nil, "", err
	}
	current, err := loadVersion(ctx, s, name, m.CurrentVersion)
	if err != nil {
		return nil, "", err
	}
	now := b.now().UTC()
	reason := needsIssuance(m, current, now)
	if reason == "" {
		return nil, "", nil
	}
	if m.Issuance == nil {
		m.Issuance = &issuanceState{}
	}
	m.Issuance.LastAttemptTime = now
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return nil, "", err
	}
	spec := *m.Managed
	return &spec, reason, nil
}

func (b *backend) obtain(ctx context.Context, s logical.Storage, spec *managedSpec) (*cert.Bundle, error) {
	n, err := loadNetwork(ctx, s)
	if err != nil {
		return nil, err
	}
	network, err := n.network()
	if err != nil {
		return nil, err
	}
	account, err := b.registeredAccount(ctx, s, spec.Account, network)
	if err != nil {
		return nil, err
	}
	dnsEntry, err := loadDNS(ctx, s, spec.DNSProvider)
	if err != nil {
		return nil, err
	}
	if dnsEntry == nil {
		return nil, fmt.Errorf("no DNS provider named %q", spec.DNSProvider)
	}
	provider, err := dnsEntry.provider(n)
	if err != nil {
		return nil, err
	}

	key, err := cert.GenerateKey(spec.KeyType)
	if err != nil {
		return nil, err
	}
	chain, err := acmeclient.Obtain(ctx, account, provider, spec.Names, key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := cert.EncodeKey(key)
	if err != nil {
		return nil, err
	}
	bundle, err := cert.Parse(string(chain), keyPEM, b.now())
	if err != nil {
		return nil, fmt.Errorf("the CA's certificate does not validate: %w", err)
	}
	if !slices.Equal(cert.Names(bundle.Leaf), spec.Names) {
		return nil, fmt.Errorf("the CA issued a certificate for %v, not %v", cert.Names(bundle.Leaf), spec.Names)
	}
	return bundle, nil
}

// registeredAccount returns the account ready for orders, registering it
// first if it is not yet registered.
func (b *backend) registeredAccount(ctx context.Context, s logical.Storage, name string, network *acmeclient.Network) (*acmeclient.Account, error) {
	l := b.lock(accountLockName(name))
	l.Lock()
	defer l.Unlock()

	a, err := loadAccount(ctx, s, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no account named %q", name)
	}
	client, err := a.client()
	if err != nil {
		return nil, err
	}
	client.Network = network
	if a.Registration != nil {
		return client, nil
	}

	if !a.TermsOfServiceAgreed {
		return nil, fmt.Errorf("account %q is not registered, and its terms of service have not been agreed to", name)
	}
	reg, _, err := acmeclient.Register(ctx, client, true)
	if err != nil {
		return nil, fmt.Errorf("registering account %q: %w", name, err)
	}
	now := b.now().UTC()
	a.Registration = &accountRegistration{
		AccountURL:     reg.AccountURL,
		Status:         reg.Status,
		Contact:        reg.Contact,
		TermsOfService: reg.TermsOfService,
		RegisteredTime: now,
		CheckedTime:    now,
	}
	if err := putJSON(ctx, s, accountKey(name), a); err != nil {
		return nil, err
	}
	client.AccountURL = reg.AccountURL
	return client, nil
}

func (b *backend) recordIssuance(ctx context.Context, s logical.Storage, name string, spec *managedSpec, bundle *cert.Bundle, issueErr error) error {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, s, name)
	if err != nil {
		return err
	}
	if m == nil || m.Managed == nil || !m.Managed.DefinedTime.Equal(spec.DefinedTime) {
		if issueErr != nil {
			return issueErr
		}
		b.Logger().Info("discarding a certificate whose definition changed or was removed while it was obtained", "certificate", name)
		return nil
	}
	if m.Issuance == nil {
		m.Issuance = &issuanceState{}
	}
	now := b.now().UTC()

	if issueErr != nil {
		if errors.Is(issueErr, context.Canceled) {
			return issueErr
		}
		msg := issueErr.Error()
		if len(msg) > maxErrorLength {
			msg = msg[:maxErrorLength]
		}
		m.Issuance.Failures++
		m.Issuance.LastError = msg
		m.Issuance.NextAttemptTime = now.Add(backoff(m.Issuance.Failures))
		if err := putJSON(ctx, s, metaKey(name), m); err != nil {
			return err
		}
		return issueErr
	}

	v, err := writeVersion(ctx, s, name, m, bundle, spec.source(), nil, now)
	if err != nil {
		return err
	}
	m.Issuance = &issuanceState{LastAttemptTime: m.Issuance.LastAttemptTime, LastSuccessTime: now}
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return err
	}
	b.Logger().Info("stored a new certificate", "certificate", name, "version", v.Version, "not_after", v.Description.NotAfter)
	return nil
}
