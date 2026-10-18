// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
)

const cleanupRetry = time.Hour

// inflightEntry is stored at certs/<name>/inflight while an attempt runs,
// so that a restart can recover what the attempt left behind: a
// certificate the CA issued but the engine never stored, and challenge
// records it published but never removed.
type inflightEntry struct {
	StartTime   time.Time `json:"start_time"`
	DefinedTime time.Time `json:"defined_time"`
	Reason      string    `json:"reason"`
	Account     string    `json:"account"`
	DNSProvider string    `json:"dns_provider"`
	// Privkey is the key the order's certificate is for; empty once only
	// clean-up remains.
	Privkey  string `json:"privkey,omitempty"`
	OrderURL string `json:"order_url,omitempty"`
	// Published are challenge records not yet removed.
	Published       []publishedRecord `json:"published,omitempty"`
	NextCleanupTime time.Time         `json:"next_cleanup_time,omitzero"`
}

type publishedRecord struct {
	Domain        string    `json:"domain"`
	Token         string    `json:"token"`
	KeyAuth       string    `json:"key_auth"`
	PublishedTime time.Time `json:"published_time"`
	// PresentError is set when publishing failed, so the record most
	// likely does not exist.
	PresentError string `json:"present_error,omitempty"`
	CleanupError string `json:"cleanup_error,omitempty"`
}

func inflightKey(name string) string {
	return "certs/" + name + "/inflight"
}

func loadInflight(ctx context.Context, s logical.Storage, name string) (*inflightEntry, error) {
	var e inflightEntry
	ok, err := getJSON(ctx, s, inflightKey(name), &e)
	if err != nil || !ok {
		return nil, err
	}
	return &e, nil
}

// updateInflight changes the in-flight entry under the certificate's lock.
func (b *backend) updateInflight(ctx context.Context, s logical.Storage, name string, change func(*inflightEntry)) error {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()
	e, err := loadInflight(ctx, s, name)
	if err != nil || e == nil {
		return err
	}
	change(e)
	return putJSON(ctx, s, inflightKey(name), e)
}

// finishInflight removes the entry, or keeps just its unremoved records.
// The caller holds the certificate's lock.
func finishInflight(ctx context.Context, s logical.Storage, name string, now time.Time) error {
	e, err := loadInflight(ctx, s, name)
	if err != nil || e == nil {
		return err
	}
	if len(e.Published) == 0 {
		return s.Delete(ctx, inflightKey(name))
	}
	e.Privkey, e.OrderURL = "", ""
	e.NextCleanupTime = now.Add(cleanupRetry)
	return putJSON(ctx, s, inflightKey(name), e)
}

// recordingProvider writes down each challenge record before publishing it
// and forgets it once removed.
type recordingProvider struct {
	inner challenge.Provider
	b     *backend
	s     logical.Storage
	name  string
}

func (p *recordingProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	rec := publishedRecord{Domain: domain, Token: token, KeyAuth: keyAuth, PublishedTime: p.b.now().UTC()}
	if err := p.b.updateInflight(ctx, p.s, p.name, func(e *inflightEntry) {
		e.Published = append(e.Published, rec)
	}); err != nil {
		return fmt.Errorf("recording the challenge record: %w", err)
	}
	err := p.inner.Present(ctx, domain, token, keyAuth)
	if err != nil {
		_ = p.b.updateInflight(context.WithoutCancel(ctx), p.s, p.name, func(e *inflightEntry) {
			for i := range e.Published {
				if e.Published[i].Domain == domain && e.Published[i].Token == token {
					e.Published[i].PresentError = err.Error()
				}
			}
		})
	}
	return err
}

func (p *recordingProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	err := p.inner.CleanUp(ctx, domain, token, keyAuth)
	if uerr := p.b.updateInflight(context.WithoutCancel(ctx), p.s, p.name, func(e *inflightEntry) {
		e.Published = settleRecord(e.Published, domain, token, err)
	}); uerr != nil && err == nil {
		err = uerr
	}
	return err
}

func (p *recordingProvider) Timeout() (time.Duration, time.Duration) {
	if t, ok := p.inner.(challenge.ProviderTimeout); ok {
		return t.Timeout()
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

// sequentialRecordingProvider keeps lego's sequential handling, which
// providers such as dnsupdate ask for.
type sequentialRecordingProvider struct {
	*recordingProvider
	seq interface{ Sequential() time.Duration }
}

func (p *sequentialRecordingProvider) Sequential() time.Duration { return p.seq.Sequential() }

func (b *backend) recording(inner challenge.Provider, s logical.Storage, name string) challenge.Provider {
	rp := &recordingProvider{inner: inner, b: b, s: s, name: name}
	if seq, ok := inner.(interface{ Sequential() time.Duration }); ok {
		return &sequentialRecordingProvider{recordingProvider: rp, seq: seq}
	}
	return rp
}

// settleRecord drops a removed record, or one that was never published,
// and otherwise notes why it could not be removed.
func settleRecord(recs []publishedRecord, domain, token string, cleanupErr error) []publishedRecord {
	i := slices.IndexFunc(recs, func(r publishedRecord) bool { return r.Domain == domain && r.Token == token })
	if i < 0 {
		return recs
	}
	if cleanupErr == nil || recs[i].PresentError != "" {
		return slices.Delete(recs, i, i+1)
	}
	recs[i].CleanupError = cleanupErr.Error()
	return recs
}

// inflightDue reports whether an in-flight entry needs recovering now: one
// left by an attempt that is no longer running.
func inflightDue(e *inflightEntry, now time.Time) bool {
	return e != nil && (e.OrderURL != "" || e.Privkey != "" || !now.Before(e.NextCleanupTime))
}

// recover deals with what an interrupted attempt left: it removes leftover
// challenge records and stores a certificate the CA had already issued. It
// runs in the certificate's background job, so no attempt is running.
func (b *backend) recover(ctx context.Context, s logical.Storage, name string) error {
	e, err := loadInflight(ctx, s, name)
	if err != nil || e == nil || !inflightDue(e, b.now()) {
		return err
	}

	if len(e.Published) > 0 {
		b.cleanupLeftovers(ctx, s, name, e)
	}
	if e.OrderURL != "" && e.Privkey != "" {
		if err := b.recoverOrder(ctx, s, name, e); err != nil {
			b.Logger().Warn("could not recover the interrupted order; a new one will be placed", "certificate", name, "order", e.OrderURL, "error", err)
		}
	}

	l := b.lock(name)
	l.Lock()
	defer l.Unlock()
	return finishInflight(ctx, s, name, b.now().UTC())
}

func (b *backend) cleanupLeftovers(ctx context.Context, s logical.Storage, name string, e *inflightEntry) {
	var provider challenge.Provider
	dnsEntry, err := loadDNS(ctx, s, e.DNSProvider)
	switch {
	case err != nil:
	case dnsEntry == nil:
		err = fmt.Errorf("no DNS provider named %q", e.DNSProvider)
	default:
		var n *networkEntry
		if n, err = loadNetwork(ctx, s); err == nil {
			provider, err = dnsEntry.provider(n)
		}
	}
	for _, rec := range e.Published {
		cleanupErr := err
		if provider != nil {
			cleanupErr = provider.CleanUp(ctx, rec.Domain, rec.Token, rec.KeyAuth)
		}
		if cleanupErr != nil {
			b.Logger().Warn("could not remove a challenge record left by an interrupted attempt", "certificate", name, "domain", rec.Domain, "error", cleanupErr)
		}
		_ = b.updateInflight(ctx, s, name, func(e *inflightEntry) {
			e.Published = settleRecord(e.Published, rec.Domain, rec.Token, cleanupErr)
		})
	}
}

// recoverOrder stores the certificate of an order the CA completed while
// the engine was not looking.
func (b *backend) recoverOrder(ctx context.Context, s logical.Storage, name string, e *inflightEntry) error {
	m, current, err := b.loadCurrent(ctx, s, name)
	if err != nil || m == nil || m.Managed == nil || !m.Managed.DefinedTime.Equal(e.DefinedTime) {
		return err
	}
	n, err := loadNetwork(ctx, s)
	if err != nil {
		return err
	}
	network, err := n.network()
	if err != nil {
		return err
	}
	account, err := b.registeredAccount(ctx, s, e.Account, network)
	if err != nil {
		return err
	}
	state, err := acmeclient.FetchOrder(ctx, account, e.OrderURL)
	if err != nil {
		return err
	}
	if state.Chain == nil {
		return fmt.Errorf("the order is %s, not valid", state.Status)
	}
	bundle, err := cert.Parse(string(state.Chain), e.Privkey, b.now())
	if err != nil {
		return fmt.Errorf("the order's certificate does not validate: %w", err)
	}
	if current != nil && current.Description.SHA256 == bundle.Describe().SHA256 {
		return nil
	}
	spec := *m.Managed
	attempt := attemptRecord{StartTime: e.StartTime, Reason: "recovered after an interruption: " + e.Reason}
	_, err = b.recordIssuance(ctx, s, name, &spec, bundle, nil, attempt)
	return err
}

// clearInflightKey forgets an attempt's key if it is one of the destroyed
// ones. The attempt cannot then be recovered, and its result will not be
// stored. The caller holds the certificate's lock.
func clearInflightKey(ctx context.Context, s logical.Storage, name string, destroyed map[string]bool) error {
	e, err := loadInflight(ctx, s, name)
	if err != nil || e == nil || e.Privkey == "" {
		return err
	}
	key, err := cert.ParseKey(e.Privkey)
	if err != nil {
		return err
	}
	spki, err := cert.SPKISHA256(key.Public())
	if err != nil || !destroyed[spki] {
		return err
	}
	e.Privkey, e.OrderURL = "", ""
	return putJSON(ctx, s, inflightKey(name), e)
}
