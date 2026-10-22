// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
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

	ariDefaultRecheck = 6 * time.Hour
	ariMinRecheck     = time.Hour
	ariMaxRecheck     = 24 * time.Hour
	ariFailedRecheck  = time.Hour

	scheduleARI     = "ari"
	scheduleDefault = "default"
)

// managedSpec defines a certificate the engine obtains itself.
type managedSpec struct {
	Names   []string `json:"names"`
	KeyType string   `json:"key_type"`
	Account string   `json:"account"`
	DNS     string   `json:"dns_provider"`
	// ReuseKey renews with the current version's key, so its public key
	// stays the same for consumers that pin it.
	ReuseKey    bool      `json:"reuse_key,omitempty"`
	DefinedTime time.Time `json:"defined_time"`
}

// issuanceState is the outcome of the engine's attempts so far.
type issuanceState struct {
	LastAttemptTime time.Time `json:"last_attempt_time,omitzero"`
	LastSuccessTime time.Time `json:"last_success_time,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
	Failures        int       `json:"failures,omitempty"`
	// FailingSince is when the current run of failures began.
	FailingSince    time.Time `json:"failing_since,omitzero"`
	NextAttemptTime time.Time `json:"next_attempt_time,omitzero"`
	// RenewRequested is set by certs/<name>/renew until a certificate is
	// stored.
	RenewRequested bool `json:"renew_requested,omitempty"`
	// RotateKey asks for a new key at the next issuance, despite
	// ReuseKey.
	RotateKey bool `json:"rotate_key,omitempty"`
	// Attempts are the most recent attempts, newest first.
	Attempts []attemptRecord `json:"attempts,omitempty"`
}

const maxAttempts = 10

// markFailing records when the current run of failures began, before an
// attempt starting at start is counted as failed. Entries written before
// failing_since existed take it from the attempt history.
func (st *issuanceState) markFailing(start time.Time) {
	if !st.FailingSince.IsZero() {
		return
	}
	st.FailingSince = start
	if st.Failures == 0 {
		return
	}
	for _, a := range st.Attempts {
		if a.Outcome != "failed" {
			break
		}
		st.FailingSince = a.StartTime
	}
}

// attemptRecord is one finished attempt to obtain a certificate.
type attemptRecord struct {
	StartTime       time.Time `json:"start_time"`
	DurationSeconds float64   `json:"duration_seconds"`
	Reason          string    `json:"reason"`
	// Outcome is "issued" or "failed".
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
	Version int    `json:"version,omitempty"`
}

func (st *issuanceState) addAttempt(a attemptRecord) {
	st.Attempts = append([]attemptRecord{a}, st.Attempts...)
	if len(st.Attempts) > maxAttempts {
		st.Attempts = st.Attempts[:maxAttempts]
	}
}

// renewalSchedule says when to renew one version, identified by its
// fingerprint.
type renewalSchedule struct {
	ForSHA256 string    `json:"for_sha256"`
	RenewAt   time.Time `json:"renew_at"`
	// Source is "ari" when RenewAt lies in the CA's suggested window, or
	// "default" for a third of the lifetime before expiry.
	Source         string    `json:"source"`
	WindowStart    time.Time `json:"window_start,omitzero"`
	WindowEnd      time.Time `json:"window_end,omitzero"`
	ExplanationURL string    `json:"explanation_url,omitempty"`
	ARIError       string    `json:"ari_error,omitempty"`
	CheckedTime    time.Time `json:"checked_time"`
	NextCheckTime  time.Time `json:"next_check_time"`
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
	case m.Issuance != nil && m.Issuance.RenewRequested:
		return "a renewal was requested"
	case m.Renewal != nil && m.Renewal.ForSHA256 == current.Description.SHA256 && !now.Before(m.Renewal.RenewAt):
		if m.Renewal.Source == scheduleARI {
			return "renewal is due, in the CA's suggested window"
		}
		return "renewal is due, a third of the lifetime before expiry"
	}
	return ""
}

// scheduleStale reports whether the current version's renewal time needs
// working out or checking with the CA again.
func scheduleStale(m *certMeta, current *certVersion, now time.Time) bool {
	if m == nil || m.Managed == nil || current == nil {
		return false
	}
	r := m.Renewal
	return r == nil || r.ForSHA256 != current.Description.SHA256 || !now.Before(r.NextCheckTime)
}

// defaultRenewAt is a third of the lifetime before expiry, less up to a
// thirtieth of the lifetime of jitter, so certificates issued together do
// not all renew together.
func defaultRenewAt(d cert.Description) time.Time {
	lifetime := d.NotAfter.Sub(d.NotBefore)
	jitter := time.Duration(rand.Int64N(int64(lifetime/30) + 1))
	return d.NotAfter.Add(-lifetime / 3).Add(-jitter)
}

// newSchedule works out when to renew current. A previous time in the same
// window is kept, so that asking the CA again does not move it about.
func newSchedule(prev *renewalSchedule, current *certVersion, w *acmeclient.RenewalWindow, ariErr error, now time.Time) *renewalSchedule {
	sha := current.Description.SHA256
	r := &renewalSchedule{ForSHA256: sha, CheckedTime: now}

	if w == nil {
		r.Source = scheduleDefault
		r.RenewAt = defaultRenewAt(current.Description)
		if prev != nil && prev.ForSHA256 == sha && prev.Source == scheduleDefault {
			r.RenewAt = prev.RenewAt
		}
		r.NextCheckTime = now.Add(ariMaxRecheck)
		switch {
		case ariErr == nil, errors.Is(ariErr, acmeclient.ErrNoARI):
		case errors.Is(ariErr, acmeclient.ErrNoRenewalInfoForCert):
			r.ARIError = ariErr.Error()
		default:
			r.ARIError = ariErr.Error()
			r.NextCheckTime = now.Add(ariFailedRecheck)
		}
		return r
	}

	r.Source = scheduleARI
	r.WindowStart, r.WindowEnd, r.ExplanationURL = w.Start, w.End, w.ExplanationURL
	switch {
	case prev != nil && prev.ForSHA256 == sha && prev.Source == scheduleARI &&
		!prev.RenewAt.Before(w.Start) && !prev.RenewAt.After(w.End):
		r.RenewAt = prev.RenewAt
	case w.End.After(w.Start):
		r.RenewAt = w.Start.Add(time.Duration(rand.Int64N(int64(w.End.Sub(w.Start)))))
	default:
		r.RenewAt = w.Start
	}
	recheck := w.RetryAfter
	if recheck <= 0 {
		recheck = ariDefaultRecheck
	}
	r.NextCheckTime = now.Add(min(max(recheck, ariMinRecheck), ariMaxRecheck))
	return r
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
	running map[string]*job
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// job is a running piece of background work, as status shows it.
type job struct {
	Since time.Time
	// Reason is set once the job knows it is issuing, and why.
	Reason string
	// again is set when work was asked for while the job ran, too late for
	// it to see; the job then runs once more.
	again bool
}

func newIssuer() *issuer {
	ctx, cancel := context.WithCancel(context.Background())
	return &issuer{running: map[string]*job{}, ctx: ctx, cancel: cancel}
}

// start runs fn for name, or, if it is already running, has it run once
// more afterwards. It reports false only once the issuer has stopped.
func (i *issuer) start(name string, fn func(context.Context)) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ctx.Err() != nil {
		return false
	}
	if j := i.running[name]; j != nil {
		j.again = true
		return true
	}
	j := &job{Since: time.Now().UTC()}
	i.running[name] = j
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		for {
			ctx, cancel := context.WithTimeout(i.ctx, issuanceTimeout)
			fn(ctx)
			cancel()

			i.mu.Lock()
			if !j.again || i.ctx.Err() != nil {
				delete(i.running, name)
				i.mu.Unlock()
				return
			}
			j.again, j.Reason = false, ""
			i.mu.Unlock()
		}
	}()
	return true
}

func (i *issuer) setReason(name, reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if j := i.running[name]; j != nil {
		j.Reason = reason
	}
}

// job returns a copy of name's running job, or nil.
func (i *issuer) job(name string) *job {
	i.mu.Lock()
	defer i.mu.Unlock()
	if j := i.running[name]; j != nil {
		c := *j
		return &c
	}
	return nil
}

func (i *issuer) stop() {
	i.cancel()
	i.wg.Wait()
}

// startIssuance looks after name in the background: it brings the renewal
// schedule up to date and obtains a certificate if one is due.
func (b *backend) startIssuance(name string) bool {
	return b.issuer.start(name, func(ctx context.Context) {
		if err := b.maintain(ctx, b.storage, name); err != nil {
			b.Logger().Error("issuance failed", "certificate", name, "error", err)
		}
	})
}

func (b *backend) maintain(ctx context.Context, s logical.Storage, name string) error {
	if b.standby() {
		return nil
	}
	if err := b.recover(ctx, s, name); err != nil {
		b.Logger().Warn("could not recover an interrupted attempt", "certificate", name, "error", err)
	}
	if err := b.refreshSchedule(ctx, s, name); err != nil {
		b.Logger().Warn("could not update the renewal schedule", "certificate", name, "error", err)
	}
	issued, err := b.issue(ctx, s, name)
	if err != nil || !issued {
		return err
	}
	return b.refreshSchedule(ctx, s, name)
}

// refreshSchedule asks the CA when to renew the current version, if the
// schedule is missing or due for a check, and stores the answer.
func (b *backend) refreshSchedule(ctx context.Context, s logical.Storage, name string) error {
	m, current, err := b.loadCurrent(ctx, s, name)
	if err != nil || !scheduleStale(m, current, b.now()) {
		return err
	}
	leaf, err := current.leaf()
	if err != nil {
		return err
	}

	var window *acmeclient.RenewalWindow
	var ariErr error
	if account, err := b.ariAccount(ctx, s, m.Managed.Account); err != nil {
		ariErr = err
	} else {
		window, ariErr = acmeclient.GetRenewalInfo(ctx, account, leaf)
	}

	l := b.lock(name)
	l.Lock()
	defer l.Unlock()
	m, latest, err := loadCurrentLocked(ctx, s, name)
	if err != nil || m == nil || m.Managed == nil || latest == nil || latest.Description.SHA256 != current.Description.SHA256 {
		return err
	}
	m.Renewal = newSchedule(m.Renewal, latest, window, ariErr, b.now().UTC())
	return putJSON(ctx, s, metaKey(name), m)
}

// ariAccount returns the account to ask the CA through; renewal information
// needs no registration.
func (b *backend) ariAccount(ctx context.Context, s logical.Storage, name string) (*acmeclient.Account, error) {
	a, err := loadAccount(ctx, s, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no account named %q", name)
	}
	if a.DirectoryURL == "" {
		return nil, fmt.Errorf("account %q has no directory_url", name)
	}
	client, err := a.client()
	if err != nil {
		return nil, err
	}
	n, err := loadNetwork(ctx, s)
	if err != nil {
		return nil, err
	}
	if client.Network, err = n.network(); err != nil {
		return nil, err
	}
	return client, nil
}

func (b *backend) loadCurrent(ctx context.Context, s logical.Storage, name string) (*certMeta, *certVersion, error) {
	l := b.lock(name)
	l.RLock()
	defer l.RUnlock()
	return loadCurrentLocked(ctx, s, name)
}

func loadCurrentLocked(ctx context.Context, s logical.Storage, name string) (*certMeta, *certVersion, error) {
	m, err := loadMeta(ctx, s, name)
	if err != nil || m == nil {
		return nil, nil, err
	}
	current, err := loadVersion(ctx, s, name, m.CurrentVersion)
	return m, current, err
}

// standby reports whether this node only serves reads. OpenBao runs a
// mount's periodic function on read-enabled standbys too, and work started
// there would act on the DNS provider and the CA before failing at its
// first write.
func (b *backend) standby() bool {
	return b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby | consts.ReplicationDRSecondary)
}

// periodic starts the issuances that are due, on the active node only.
func (b *backend) periodic(ctx context.Context, req *logical.Request) error {
	if b.standby() {
		return nil
	}
	names, err := listCertIDs(ctx, req.Storage, "")
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
		inflight, err := loadInflight(ctx, req.Storage, name)
		if err != nil {
			continue
		}
		if needsIssuance(m, current, now) != "" || scheduleStale(m, current, now) || inflightDue(inflight, now) {
			b.startIssuance(name)
		}
	}
	return nil
}

// issue obtains and stores a certificate for name if it needs one, and
// reports whether it stored one. Failures are recorded in the
// certificate's issuance state with a backoff.
func (b *backend) issue(ctx context.Context, s logical.Storage, name string) (bool, error) {
	claim, err := b.claimIssuance(ctx, s, name)
	if err != nil || claim == nil {
		return false, err
	}
	b.Logger().Info("obtaining a certificate", "certificate", name, "reason", claim.reason, "names", claim.spec.Names)
	b.issuer.setReason(name, claim.reason)

	start := b.now().UTC()
	bundle, issueErr := b.obtain(ctx, s, name, claim)
	attempt := attemptRecord{StartTime: start, DurationSeconds: b.now().Sub(start).Seconds(), Reason: claim.reason}
	return b.recordIssuance(ctx, s, name, &claim.spec, bundle, issueErr, attempt)
}

type issuanceClaim struct {
	spec     managedSpec
	reason   string
	replaces *x509.Certificate
	key      crypto.Signer
	keyPEM   string
	// reusedFrom is the version whose key is reused, or 0 for a new key.
	reusedFrom int
}

// chooseKey picks the key for an attempt: the current one when the
// definition reuses keys and it is usable, otherwise a new one.
func (b *backend) chooseKey(ctx context.Context, s logical.Storage, name string, m *certMeta, current *certVersion, claim *issuanceClaim) error {
	rotate := m.Issuance != nil && m.Issuance.RotateKey
	if m.Managed.ReuseKey && !rotate && current != nil && !current.destroyed() && current.Description.KeyType == m.Managed.KeyType {
		destroyed, err := keyDestroyed(ctx, s, name, current.Description.SPKISHA256)
		if err != nil {
			return err
		}
		if !destroyed {
			key, err := cert.ParseKey(current.Privkey)
			if err != nil {
				return fmt.Errorf("the current key: %w", err)
			}
			claim.key, claim.keyPEM, claim.reusedFrom = key, current.Privkey, current.Version
			return nil
		}
	}
	key, err := cert.GenerateKey(m.Managed.KeyType)
	if err != nil {
		return err
	}
	keyPEM, err := cert.EncodeKey(key)
	if err != nil {
		return err
	}
	claim.key, claim.keyPEM = key, keyPEM
	return nil
}

// keyDestroyed reports whether any version holding the key with this
// fingerprint has had its key destroyed: such a key is never used again.
func keyDestroyed(ctx context.Context, s logical.Storage, name, spki string) (bool, error) {
	ns, err := listVersions(ctx, s, name)
	if err != nil {
		return false, err
	}
	for _, n := range ns {
		v, err := loadVersion(ctx, s, name, n)
		if err != nil {
			return false, err
		}
		if v != nil && v.destroyed() && v.Description.SPKISHA256 == spki {
			return true, nil
		}
	}
	return false, nil
}

// claimIssuance records the start of an attempt and returns what to do, or
// nil if nothing needs doing.
func (b *backend) claimIssuance(ctx context.Context, s logical.Storage, name string) (*issuanceClaim, error) {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, current, err := loadCurrentLocked(ctx, s, name)
	if err != nil || m == nil {
		return nil, err
	}
	now := b.now().UTC()
	reason := needsIssuance(m, current, now)
	if reason == "" {
		return nil, nil
	}
	claim := &issuanceClaim{spec: *m.Managed, reason: reason}
	if err := b.chooseKey(ctx, s, name, m, current, claim); err != nil {
		return nil, err
	}

	// Written before anything reaches the CA, keeping records an earlier
	// attempt could not remove.
	inflight := &inflightEntry{
		StartTime: now, DefinedTime: m.Managed.DefinedTime, Reason: reason,
		Account: m.Managed.Account, DNS: m.Managed.DNS, Privkey: claim.keyPEM,
	}
	if prev, err := loadInflight(ctx, s, name); err != nil {
		return nil, err
	} else if prev != nil {
		inflight.Published = prev.Published
	}
	if err := putJSON(ctx, s, inflightKey(name), inflight); err != nil {
		return nil, err
	}

	if m.Issuance == nil {
		m.Issuance = &issuanceState{}
	}
	m.Issuance.LastAttemptTime = now
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return nil, err
	}

	// The CA links a renewal to its predecessor only within one account.
	if current != nil && current.Source == m.Managed.source() && !current.destroyed() {
		claim.replaces, _ = current.leaf()
	}
	return claim, nil
}

func (b *backend) obtain(ctx context.Context, s logical.Storage, name string, claim *issuanceClaim) (*cert.Bundle, error) {
	spec := &claim.spec
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
	dnsEntry, err := loadDNS(ctx, s, spec.Account, spec.DNS)
	if err != nil {
		return nil, err
	}
	if dnsEntry == nil {
		return nil, fmt.Errorf("account %q has no DNS provider named %q", spec.Account, spec.DNS)
	}
	provider, err := dnsEntry.provider(n)
	if err != nil {
		return nil, err
	}

	chain, err := acmeclient.Obtain(ctx, account, b.recording(provider, s, name), acmeclient.Order{
		Names:    spec.Names,
		Key:      claim.key,
		Replaces: claim.replaces,
		OnReplacesRefused: func(err error) {
			b.Logger().Warn("the CA refused to link the renewal to the certificate it replaces; ordering without", "certificate", name, "error", err)
		},
		OnOrderCreated: func(orderURL string) {
			if err := b.updateInflight(context.WithoutCancel(ctx), s, name, func(e *inflightEntry) { e.OrderURL = orderURL }); err != nil {
				b.Logger().Warn("could not record the order URL", "certificate", name, "error", err)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	bundle, err := cert.Parse(string(chain), claim.keyPEM, b.now())
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
	if a.DirectoryURL == "" {
		return nil, fmt.Errorf("account %q has no directory_url", name)
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
		ContactSent:    reg.ContactSent,
		TermsOfService: reg.TermsOfService,
		CAAIdentities:  reg.CAAIdentities,
		RegisteredTime: now,
		CheckedTime:    now,
	}
	if err := putJSON(ctx, s, accountKey(name), a); err != nil {
		return nil, err
	}
	client.AccountURL = reg.AccountURL
	return client, nil
}

func (b *backend) recordIssuance(ctx context.Context, s logical.Storage, name string, spec *managedSpec, bundle *cert.Bundle, issueErr error, attempt attemptRecord) (bool, error) {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, s, name)
	if err != nil {
		return false, err
	}
	now := b.now().UTC()
	defer func() {
		if err := finishInflight(context.WithoutCancel(ctx), s, name, now); err != nil {
			b.Logger().Warn("could not clear the in-flight record", "certificate", name, "error", err)
		}
	}()
	if m == nil || m.Managed == nil || !m.Managed.DefinedTime.Equal(spec.DefinedTime) {
		if issueErr != nil {
			return false, issueErr
		}
		b.Logger().Info("discarding a certificate whose definition changed or was removed while it was obtained", "certificate", name)
		return false, nil
	}
	if m.Issuance == nil {
		m.Issuance = &issuanceState{}
	}

	if issueErr != nil {
		if errors.Is(issueErr, context.Canceled) {
			return false, issueErr
		}
		msg := issueErr.Error()
		if len(msg) > maxErrorLength {
			msg = msg[:maxErrorLength]
		}
		m.Issuance.markFailing(attempt.StartTime)
		m.Issuance.Failures++
		m.Issuance.LastError = msg
		m.Issuance.NextAttemptTime = now.Add(backoff(m.Issuance.Failures))
		attempt.Outcome, attempt.Error = "failed", msg
		m.Issuance.addAttempt(attempt)
		if err := putJSON(ctx, s, metaKey(name), m); err != nil {
			return false, err
		}
		return false, issueErr
	}

	if destroyed, err := keyDestroyed(ctx, s, name, bundle.Describe().SPKISHA256); err != nil {
		return false, err
	} else if destroyed {
		msg := "the key was destroyed while the certificate was being obtained, so it is not stored"
		m.Issuance.markFailing(attempt.StartTime)
		m.Issuance.Failures++
		m.Issuance.LastError = msg
		m.Issuance.NextAttemptTime = time.Time{}
		attempt.Outcome, attempt.Error = "failed", msg
		m.Issuance.addAttempt(attempt)
		if err := putJSON(ctx, s, metaKey(name), m); err != nil {
			return false, err
		}
		return false, errors.New(msg)
	}

	v, err := writeVersion(ctx, s, name, m, bundle, spec.source(), nil, now)
	if err != nil {
		return false, err
	}
	attempt.Outcome, attempt.Version = "issued", v.Version
	history := m.Issuance.Attempts
	m.Issuance = &issuanceState{LastAttemptTime: m.Issuance.LastAttemptTime, LastSuccessTime: now, Attempts: history}
	m.Issuance.addAttempt(attempt)
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return false, err
	}
	b.Logger().Info("stored a new certificate", "certificate", name, "version", v.Version, "not_after", v.Description.NotAfter)
	return true, nil
}
