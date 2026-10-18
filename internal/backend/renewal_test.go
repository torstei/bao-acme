// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

func (e *managedEnv) periodic() {
	e.t.Helper()
	if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
		e.t.Fatal(err)
	}
}

// advance moves the engine's clock to just after t.
func (e *managedEnv) advance(t time.Time) {
	e.b.clockOffset.Store(int64(time.Until(t) + time.Minute))
}

func scheduledFor(sha string) func(*certMeta) bool {
	return func(m *certMeta) bool { return m.Renewal != nil && m.Renewal.ForSHA256 == sha }
}

func (e *managedEnv) current(name string) *certVersion {
	e.t.Helper()
	_, v, err := loadCurrentLocked(context.Background(), e.storage, name)
	if err != nil || v == nil {
		e.t.Fatalf("%s: no current version: %v", name, err)
	}
	return v
}

func TestRenewalScheduleFromARI(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v1 := e.current("www")
	m := e.waitFor("www", "a schedule", scheduledFor(v1.Description.SHA256))

	r := m.Renewal
	if r.Source != scheduleARI || r.RenewAt.Before(r.WindowStart) || r.RenewAt.After(r.WindowEnd) {
		t.Fatalf("schedule = %+v", r)
	}
	if !r.WindowStart.After(v1.Description.NotBefore) || r.WindowEnd.After(v1.Description.NotAfter) {
		t.Errorf("window %v – %v outside validity %v – %v", r.WindowStart, r.WindowEnd, v1.Description.NotBefore, v1.Description.NotAfter)
	}
	if got := r.NextCheckTime.Sub(r.CheckedTime); got < ariMinRecheck || got > ariMaxRecheck {
		t.Errorf("next check after %v", got)
	}

	info := e.ok(logical.ReadOperation, "certs/www/info", nil)
	renewal := info.Data["issuance"].(map[string]any)["renewal"].(map[string]any)
	if renewal["source"] != scheduleARI || !renewal["renew_at"].(time.Time).Equal(r.RenewAt) {
		t.Errorf("info renewal = %v", renewal)
	}
}

func TestRenewsWhenDue(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v1 := e.current("www")
	m := e.waitFor("www", "a schedule", scheduledFor(v1.Description.SHA256))

	e.periodic()
	time.Sleep(200 * time.Millisecond)
	if got := e.current("www").Version; got != 1 {
		t.Fatalf("renewed before it was due: version %d", got)
	}

	e.advance(m.Renewal.RenewAt)
	e.periodic()
	e.waitFor("www", "the renewed certificate", hasVersion(2))
	v2 := e.current("www")
	if v2.Source != "acme:le" || v2.Description.SHA256 == v1.Description.SHA256 {
		t.Errorf("renewed version = %+v", v2.Description)
	}
	e.waitFor("www", "a schedule for the new version", scheduledFor(v2.Description.SHA256))
}

func TestRenewNow(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))

	resp := e.ok(logical.UpdateOperation, "certs/www/renew", nil)
	if resp.Data["issuing"] != true {
		t.Errorf("renew = %v", resp.Data)
	}
	m := e.waitFor("www", "the renewed certificate", hasVersion(2))
	if m.Issuance.RenewRequested {
		t.Error("renew_requested still set after a successful renewal")
	}

	e.fails(logical.UpdateOperation, "certs/nope/renew", nil, "not managed")
	e.imp("plain", testcerts.New(t, testcerts.Options{}))
	e.fails(logical.UpdateOperation, "certs/plain/renew", nil, "not managed")
}

func TestRenewClearsBackoff(t *testing.T) {
	e := newManagedEnv(t)
	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.define("www", "www.example.test")
	e.waitFor("www", "a failure", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures == 1 })

	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": managedTSIGSecret})
	e.ok(logical.UpdateOperation, "certs/www/renew", nil)
	m := e.waitFor("www", "the certificate", hasVersion(1))
	if m.Issuance.Failures != 0 || m.Issuance.LastError != "" {
		t.Errorf("issuance after success = %+v", m.Issuance)
	}
}

func TestRevocationRenewsEarly(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v1 := e.current("www")
	m := e.waitFor("www", "a schedule", scheduledFor(v1.Description.SHA256))

	account, err := e.b.ariAccount(context.Background(), e.storage, "le")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := loadAccount(context.Background(), e.storage, "le")
	account.AccountURL = stored.Registration.AccountURL
	if err := acmeclient.Revoke(context.Background(), account, []byte(v1.Certificate+v1.Chain)); err != nil {
		t.Fatal(err)
	}

	// Only the scheduled re-check, not the original renewal time, is due.
	e.advance(m.Renewal.NextCheckTime)
	if !e.b.now().Before(m.Renewal.RenewAt) {
		t.Fatal("test setup: the original renewal time has already passed")
	}
	e.periodic()
	e.waitFor("www", "the early renewal", hasVersion(2))
}

func TestDefaultScheduleWithoutRenewalInfo(t *testing.T) {
	e := newManagedEnv(t)
	imported := testcerts.New(t, testcerts.Options{Names: []string{"site.example.test"}})
	e.imp("site", imported)
	e.define("site", "site.example.test")
	e.periodic()
	v := e.current("site")
	m := e.waitFor("site", "a schedule", scheduledFor(v.Description.SHA256))

	r := m.Renewal
	lifetime := v.Description.NotAfter.Sub(v.Description.NotBefore)
	latest := v.Description.NotAfter.Add(-lifetime / 3)
	if r.Source != scheduleDefault || r.RenewAt.After(latest) || r.RenewAt.Before(latest.Add(-lifetime/30)) {
		t.Errorf("schedule = %+v, want a third of %v before %v", r, lifetime, v.Description.NotAfter)
	}
	if r.ARIError == "" || r.NextCheckTime.Sub(r.CheckedTime) != ariMaxRecheck {
		t.Errorf("a certificate the CA does not know: ari_error %q, next check after %v", r.ARIError, r.NextCheckTime.Sub(r.CheckedTime))
	}
}

func TestReplacesOnlyOwnCertificates(t *testing.T) {
	e := newManagedEnv(t)
	e.imp("site", testcerts.New(t, testcerts.Options{Names: []string{"site.example.test"}}))
	e.define("site", "site.example.test")
	if err := e.b.requestRenewal(context.Background(), e.storage, "le", "site", false); err != nil {
		t.Fatal(err)
	}
	claim, err := e.b.claimIssuance(context.Background(), e.storage, "site")
	if err != nil || claim == nil {
		t.Fatalf("claim = %v, %v", claim, err)
	}
	if claim.replaces != nil {
		t.Error("an imported certificate would be named as replaced")
	}

	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	if err := e.b.requestRenewal(context.Background(), e.storage, "le", "www", false); err != nil {
		t.Fatal(err)
	}
	e.b.issuer.stop()
	claim, err = e.b.claimIssuance(context.Background(), e.storage, "www")
	if err != nil || claim == nil || claim.replaces == nil {
		t.Fatalf("own certificate not named as replaced: %+v, %v", claim, err)
	}
}

func TestNewScheduleKeepsATimeInTheWindow(t *testing.T) {
	now := time.Now().UTC()
	v := &certVersion{Description: cert.Description{SHA256: "abc", NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}}
	w := &acmeclient.RenewalWindow{Start: now.Add(59 * 24 * time.Hour), End: now.Add(61 * 24 * time.Hour), RetryAfter: 10 * time.Minute}

	first := newSchedule(nil, v, w, nil, now)
	if first.RenewAt.Before(w.Start) || first.RenewAt.After(w.End) || first.NextCheckTime.Sub(now) != ariMinRecheck {
		t.Fatalf("first = %+v", first)
	}
	again := newSchedule(first, v, w, nil, now.Add(time.Hour))
	if !again.RenewAt.Equal(first.RenewAt) {
		t.Error("an unchanged window moved the renewal time")
	}
	moved := &acmeclient.RenewalWindow{Start: now, End: now.Add(time.Hour)}
	if early := newSchedule(first, v, moved, nil, now); early.RenewAt.After(moved.End) || early.NextCheckTime.Sub(now) != ariDefaultRecheck {
		t.Errorf("a window moved earlier = %+v", early)
	}

	failed := newSchedule(first, v, nil, errors.New("connection refused"), now)
	if failed.Source != scheduleDefault || failed.NextCheckTime.Sub(now) != ariFailedRecheck || failed.ARIError == "" {
		t.Errorf("after a failed check = %+v", failed)
	}
	noARI := newSchedule(nil, v, nil, acmeclient.ErrNoARI, now)
	if noARI.ARIError != "" || noARI.NextCheckTime.Sub(now) != ariMaxRecheck {
		t.Errorf("a CA without ARI = %+v", noARI)
	}
}
