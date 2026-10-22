// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

func TestCertState(t *testing.T) {
	now := time.Now()
	spec := &managedSpec{Names: []string{"a.example"}, KeyType: "ecdsa-p256"}
	valid := &certVersion{Description: cert.Description{
		SHA256: "x", Names: []string{"a.example"}, KeyType: "ecdsa-p256",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
	}}
	expired := &certVersion{Description: cert.Description{NotAfter: now.Add(-time.Minute)}}
	due := &renewalSchedule{ForSHA256: "x", RenewAt: now.Add(-time.Minute)}
	notDue := &renewalSchedule{ForSHA256: "x", RenewAt: now.Add(time.Hour)}
	failed := &issuanceState{Failures: 2}
	issuing := &job{Since: now, Reason: "renewal is due"}
	refreshing := &job{Since: now}

	cases := []struct {
		name    string
		m       *certMeta
		current *certVersion
		running *job
		want    string
	}{
		{"imported, valid", &certMeta{}, valid, nil, stateValid},
		{"imported, expired", &certMeta{}, expired, nil, stateExpired},
		{"managed, not due", &certMeta{Managed: spec, Renewal: notDue}, valid, nil, stateValid},
		{"managed, due", &certMeta{Managed: spec, Renewal: due}, valid, nil, stateRenewalDue},
		{"managed, renewing", &certMeta{Managed: spec, Renewal: due}, valid, issuing, stateRenewing},
		{"managed, only checking the schedule", &certMeta{Managed: spec, Renewal: notDue}, valid, refreshing, stateValid},
		{"managed, failing renewals", &certMeta{Managed: spec, Renewal: due, Issuance: failed}, valid, nil, stateFailing},
		{"expired beats renewing", &certMeta{Managed: spec}, expired, issuing, stateExpired},
		{"first issuance pending", &certMeta{Managed: spec}, nil, nil, statePending},
		{"first issuance running", &certMeta{Managed: spec}, nil, issuing, stateIssuing},
		{"first issuance failing", &certMeta{Managed: spec, Issuance: failed}, nil, nil, stateFailing},
	}
	for _, c := range cases {
		if got := certState(c.m, c.current, c.running, now); got != c.want {
			t.Errorf("%s: state = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestStatusOfImportedCertificate(t *testing.T) {
	h := newHarness(t)
	c := testcerts.New(t, testcerts.Options{NotAfter: time.Now().Add(10 * 24 * time.Hour)})
	h.imp("a", c)

	s := h.ok(logical.ReadOperation, "certs/a/status", nil)
	if s.Data["state"] != stateValid || s.Data["managed"] != false || s.Data["running"] != false {
		t.Errorf("status = %v", s.Data)
	}
	if in := s.Data["expires_in"].(int64); in < 9*24*3600 || in > 10*24*3600 {
		t.Errorf("expires_in = %d", in)
	}
	if attempts := s.Data["attempts"].([]map[string]any); len(attempts) != 0 {
		t.Errorf("attempts = %v", attempts)
	}

	h.b.clockOffset.Store(int64(11 * 24 * time.Hour))
	if s := h.ok(logical.ReadOperation, "certs/a/status", nil); s.Data["state"] != stateExpired || s.Data["expires_in"].(int64) >= 0 {
		t.Errorf("after expiry: %v", s.Data)
	}
	if resp, _ := h.do(logical.ReadOperation, "certs/missing/status", nil); resp != nil {
		t.Errorf("status of a missing certificate = %v", resp.Data)
	}
}

func TestStatusRecordsAttempts(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	e.waitFor("www", "a schedule", func(m *certMeta) bool { return m.Renewal != nil })

	s := e.ok(logical.ReadOperation, "certs/www/status", nil)
	if s.Data["state"] != stateValid || s.Data["version"] != 1 || s.Data["renew_at"] == nil {
		t.Errorf("status = %v", s.Data)
	}
	for _, k := range []string{"failing_since", "last_error"} {
		if _, ok := e.ok(logical.ReadOperation, "status", nil).Data["certificates"].(map[string]any)[e.id("www")].(map[string]any)[k]; ok {
			t.Errorf("mount status of an issued certificate shows %s", k)
		}
	}
	attempts := s.Data["attempts"].([]map[string]any)
	if len(attempts) != 1 || attempts[0]["outcome"] != "issued" || attempts[0]["version"] != 1 || attempts[0]["reason"] != "no certificate yet" {
		t.Fatalf("attempts = %v", attempts)
	}

	// The CA would reuse the authorization it just validated, so a renewal
	// with a broken DNS provider would succeed; a new name needs a fresh
	// authorization, and fails.
	e.ok(logical.UpdateOperation, "config/dns/bind", map[string]any{"tsig_secret": "d3Jvbmd3cm9uZ3dyb25nd3Jvbmd3cm9uZw=="})
	e.define("www", "www.example.test", "new.example.test")
	e.waitFor("www", "a failed renewal", func(m *certMeta) bool { return m.Issuance != nil && m.Issuance.Failures == 1 })

	s = e.ok(logical.ReadOperation, "certs/www/status", nil)
	if s.Data["state"] != stateFailing || s.Data["last_error"] == "" {
		t.Errorf("status after a failed renewal = %v", s.Data)
	}
	attempts = s.Data["attempts"].([]map[string]any)
	if len(attempts) != 2 || attempts[0]["outcome"] != "failed" || attempts[0]["error"] == "" || attempts[0]["reason"] != "the current certificate does not match the definition" || attempts[1]["outcome"] != "issued" {
		t.Errorf("attempts, newest first = %v", attempts)
	}
	mount := e.ok(logical.ReadOperation, "status", nil).Data["certificates"].(map[string]any)[e.id("www")].(map[string]any)
	if mount["failing_since"] != attempts[0]["start_time"] || mount["last_error"] != attempts[0]["error"] {
		t.Errorf("mount status of a failing certificate = %v", mount)
	}

	e.define("www", "www.example.test", "api.example.test")
	if m, _ := loadMeta(t.Context(), e.storage, e.id("www")); m.Issuance == nil || len(m.Issuance.Attempts) < 2 {
		t.Error("a new definition dropped the attempt history")
	}
}

func TestStatusShowsRunningJob(t *testing.T) {
	h := newHarness(t)
	h.imp("a", testcerts.New(t, testcerts.Options{}))
	h.b.issuer.mu.Lock()
	h.b.issuer.running[h.id("a")] = &job{Since: time.Now().Add(-time.Minute), Reason: "a renewal was requested"}
	h.b.issuer.mu.Unlock()

	s := h.ok(logical.ReadOperation, "certs/a/status", nil)
	if s.Data["running"] != true || s.Data["running_reason"] != "a renewal was requested" || s.Data["state"] != stateRenewing {
		t.Errorf("status = %v", s.Data)
	}
}

func TestMountStatus(t *testing.T) {
	h := newHarness(t)
	h.imp("ok", testcerts.New(t, testcerts.Options{NotAfter: time.Now().Add(30 * 24 * time.Hour)}))
	h.imp("soon", testcerts.New(t, testcerts.Options{NotAfter: time.Now().Add(2 * 24 * time.Hour)}))
	h.b.clockOffset.Store(int64(3 * 24 * time.Hour))

	s := h.ok(logical.ReadOperation, "status", nil)
	counts := s.Data["counts"].(map[string]int)
	if s.Data["total"] != 2 || counts[stateValid] != 1 || counts[stateExpired] != 1 || counts[stateFailing] != 0 {
		t.Errorf("status = %v", s.Data)
	}
	certs := s.Data["certificates"].(map[string]any)
	if certs[h.id("soon")].(map[string]any)["state"] != stateExpired {
		t.Errorf("certificates = %v", certs)
	}
}

func TestMountStatusShowsAccountsAndLeftovers(t *testing.T) {
	h := newHarness(t)
	h.ok(logical.CreateOperation, "config/accounts/empty", nil)
	h.imp("a", testcerts.New(t, testcerts.Options{}))
	published := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := putJSON(context.Background(), h.storage, inflightKey(h.id("a")), &inflightEntry{
		Account: "t", DNS: "bind", NextCleanupTime: time.Now().Add(time.Hour),
		Published: []publishedRecord{{Domain: "a.example.test", Token: "tok", PublishedTime: published, CleanupError: "refused"}},
	}); err != nil {
		t.Fatal(err)
	}

	s := h.ok(logical.ReadOperation, "status", nil)
	accounts := s.Data["accounts"].(map[string]any)
	if len(accounts) != 2 || accounts["empty"] == nil {
		t.Errorf("accounts = %v", accounts)
	}
	if a := accounts["t"].(map[string]any); a["registered"] != false || a["terms_of_service_agreed"] != false {
		t.Errorf("account t = %v", a)
	}
	cert := s.Data["certificates"].(map[string]any)[h.id("a")].(map[string]any)
	leftovers, _ := cert["leftovers"].([]map[string]any)
	if len(leftovers) != 1 || leftovers[0]["domain"] != "a.example.test" || leftovers[0]["cleanup_error"] != "refused" || leftovers[0]["published_time"] != published {
		t.Errorf("leftovers = %v", cert["leftovers"])
	}
	for _, k := range []string{"failing_since", "last_error"} {
		if _, ok := cert[k]; ok {
			t.Errorf("a certificate that is not failing shows %s", k)
		}
	}

	if got := h.ok(logical.ReadOperation, "accounts/t/status", nil).Data["accounts"].(map[string]any); len(got) != 1 || got["t"] == nil {
		t.Errorf("the account's status shows accounts %v", got)
	}

	h.b.issuer.mu.Lock()
	h.b.issuer.running[h.id("a")] = &job{Since: time.Now(), Reason: "a renewal was requested"}
	h.b.issuer.mu.Unlock()
	cert = h.ok(logical.ReadOperation, "status", nil).Data["certificates"].(map[string]any)[h.id("a")].(map[string]any)
	if _, ok := cert["leftovers"]; ok {
		t.Error("a running attempt's records are shown as leftovers")
	}
}

func TestMarkFailing(t *testing.T) {
	t0 := time.Now().UTC()
	at := func(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

	st := &issuanceState{}
	st.markFailing(at(5))
	if !st.FailingSince.Equal(at(5)) {
		t.Errorf("first failure: %v", st.FailingSince)
	}
	st.Failures = 1
	st.markFailing(at(6))
	if !st.FailingSince.Equal(at(5)) {
		t.Errorf("a later failure moved failing_since: %v", st.FailingSince)
	}

	old := &issuanceState{Failures: 2, Attempts: []attemptRecord{
		{StartTime: at(4), Outcome: "failed"}, {StartTime: at(3), Outcome: "failed"}, {StartTime: at(1), Outcome: "issued"},
	}}
	old.markFailing(at(5))
	if !old.FailingSince.Equal(at(3)) {
		t.Errorf("from the history: %v, want the run's first failure", old.FailingSince)
	}

	redefined := &issuanceState{Attempts: []attemptRecord{{StartTime: at(4), Outcome: "failed"}}}
	redefined.markFailing(at(5))
	if !redefined.FailingSince.Equal(at(5)) {
		t.Errorf("after a redefinition: %v, want the new failure", redefined.FailingSince)
	}
}

func TestAttemptHistoryIsCapped(t *testing.T) {
	st := &issuanceState{}
	for i := range maxAttempts + 5 {
		st.addAttempt(attemptRecord{Version: i})
	}
	if len(st.Attempts) != maxAttempts || st.Attempts[0].Version != maxAttempts+4 {
		t.Errorf("attempts = %d, newest %d", len(st.Attempts), st.Attempts[0].Version)
	}
}

func TestStartDuringARunningJobRunsAgain(t *testing.T) {
	i := newIssuer()
	t.Cleanup(i.stop)
	release := make(chan struct{})
	runs := make(chan int, 3)
	n := 0
	fn := func(context.Context) {
		n++
		runs <- n
		if n == 1 {
			<-release
		}
	}

	if !i.start("a", fn) {
		t.Fatal("first start refused")
	}
	<-runs
	if !i.start("a", fn) || !i.start("a", fn) {
		t.Fatal("a start during a running job was refused")
	}
	close(release)
	select {
	case got := <-runs:
		if got != 2 {
			t.Fatalf("run %d", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the job did not run again")
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case got := <-runs:
		t.Errorf("two starts during one job ran it %d times", got)
	default:
	}
	if i.job("a") != nil {
		t.Error("job still listed as running")
	}
}
