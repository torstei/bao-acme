// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

// On a read-enabled standby, the periodic function must neither start
// issuances nor recover in-flight entries: those belong to the active node,
// and a standby acting on them would remove the active node's challenge
// records.
func TestNoBackgroundWorkOnAStandby(t *testing.T) {
	e := newManagedEnv(t)
	ctx := context.Background()
	e.system.setState(consts.ReplicationPerformanceStandby)

	spec := e.defineQuietly("www", "www.example.test")
	dnsEntry, _ := loadDNS(ctx, e.storage, "bind")
	provider, err := dnsEntry.provider(&networkEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Present(ctx, "www.example.test", "tok", testKeyAuth); err != nil {
		t.Fatal(err)
	}
	inflight := &inflightEntry{
		StartTime: time.Now().UTC(), DefinedTime: spec.DefinedTime, Reason: "no certificate yet",
		Account: "le", DNS: "bind",
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", KeyAuth: testKeyAuth, PublishedTime: time.Now().UTC()}},
	}
	if err := putJSON(ctx, e.storage, inflightKey("www"), inflight); err != nil {
		t.Fatal(err)
	}

	e.periodic()
	if j := e.b.issuer.job("www"); j != nil {
		t.Errorf("the periodic function started a job on a standby: %+v", j)
	}
	// A job started anyway, say by a request just before the node stepped
	// down, must also leave things alone.
	e.b.startIssuance("www")
	time.Sleep(300 * time.Millisecond)

	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 1 {
		t.Errorf("a standby touched the active node's challenge record: TXT = %v", got)
	}
	if i := e.inflight("www"); i == nil || len(i.Published) != 1 || i.Published[0].CleanupError != "" {
		t.Errorf("a standby changed the in-flight entry: %+v", i)
	}
	if m, _ := loadMeta(ctx, e.storage, "www"); m.CurrentVersion != 0 || m.Issuance != nil {
		t.Errorf("a standby attempted an issuance: %+v", m)
	}

	e.system.setState(0)
	e.periodic()
	e.waitFor("www", "the certificate, once the node is active", hasVersion(1))
	if got := e.dns.TXT("_acme-challenge.www.example.test"); len(got) != 0 {
		t.Errorf("the active node left the challenge record: %v", got)
	}
}
