// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/testcerts"
)

// TestIDsTellReCreatedApart: an account, DNS provider or certificate made
// again under an old name gets a new id; one that is only changed keeps its
// id.
func TestIDsTellReCreatedApart(t *testing.T) {
	h := newHarness(t)
	importC := func() map[string]any {
		c := testcerts.New(t, testcerts.Options{})
		return map[string]any{"fullchain": c.Fullchain, "privkey": c.Privkey}
	}
	cases := []struct {
		kind, path, read string
		create, change   func()
		remove           func()
	}{
		{
			kind: "account", path: "config/accounts/test", read: "config/accounts/test",
			create: func() { h.ok(logical.CreateOperation, "config/accounts/test", nil) },
			change: func() {
				h.ok(logical.UpdateOperation, "config/accounts/test", map[string]any{"email": "a@example.com"})
			},
			remove: func() { h.ok(logical.DeleteOperation, "config/accounts/test", nil) },
		},
		{
			kind: "DNS provider", path: "config/dns/d", read: "config/dns/d",
			create: func() {
				h.ok(logical.CreateOperation, "config/dns/d", map[string]any{"type": "domeneshop", "api_token": "t", "api_secret": "s"})
			},
			change: func() { h.ok(logical.UpdateOperation, "config/dns/d", map[string]any{"ttl": 60}) },
			remove: func() { h.ok(logical.DeleteOperation, "config/dns/d", nil) },
		},
		{
			kind: "certificate", path: "certs/c", read: "certs/c/info",
			create: func() { h.ok(logical.UpdateOperation, "certs/c/import", importC()) },
			change: func() { h.ok(logical.UpdateOperation, "certs/c/import", importC()) },
			remove: func() { h.ok(logical.DeleteOperation, "certs/c", nil) },
		},
	}
	for _, c := range cases {
		c.create()
		first, _ := h.ok(logical.ReadOperation, c.read, nil).Data["id"].(string)
		if len(first) != 36 {
			t.Fatalf("%s id = %q", c.kind, first)
		}
		c.change()
		if got := h.ok(logical.ReadOperation, c.read, nil).Data["id"]; got != first {
			t.Errorf("changing the %s changed its id: %v, was %s", c.kind, got, first)
		}
		c.remove()
		c.create()
		if got := h.ok(logical.ReadOperation, c.read, nil).Data["id"]; got == first {
			t.Errorf("a re-created %s has the old id", c.kind)
		}
	}
}

func TestCertificateCarriesItsIDs(t *testing.T) {
	h := newHarness(t)
	h.imp("c", testcerts.New(t, testcerts.Options{}))
	account := h.ok(logical.ReadOperation, "config/accounts/t", nil).Data["id"]
	info := h.ok(logical.ReadOperation, "certs/c/info", nil).Data
	id := info["id"]

	created, _ := info["certificate_created_time"].(time.Time)
	if created.IsZero() {
		t.Errorf("certificate_created_time = %v", info["certificate_created_time"])
	}
	h.b.clockOffset.Store(int64(time.Hour))
	h.imp("c", testcerts.New(t, testcerts.Options{}))
	later := h.ok(logical.ReadOperation, "certs/c/info", nil).Data
	if later["certificate_created_time"] != created {
		t.Errorf("a new version changed certificate_created_time: %v, was %v", later["certificate_created_time"], created)
	}
	if v, _ := later["created_time"].(time.Time); !v.After(created) {
		t.Errorf("info created_time = %v, want the current version's, after %v", v, created)
	}
	if info["account_id"] != account {
		t.Errorf("version account_id = %v, account id %v", info["account_id"], account)
	}
	if read := h.ok(logical.ReadOperation, "certs/c", nil).Data; read["id"] != id || read["account_id"] != account {
		t.Errorf("read id %v, account_id %v", read["id"], read["account_id"])
	}
	if s := h.ok(logical.ReadOperation, "status", nil).Data["certificates"].(map[string]any)[h.id("c")].(map[string]any); s["id"] != id {
		t.Errorf("status id = %v", s["id"])
	}
}

// TestAccountsStoredWithoutAnIDGetOne: accounts from before v0.5.0 keep
// their settings and get an id at start, which then stays.
func TestAccountsStoredWithoutAnIDGetOne(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.storedAccount("t")
	a.ID = ""
	if err := putJSON(ctx, h.storage, accountKey("t"), a); err != nil {
		t.Fatal(err)
	}
	init := func() string {
		if err := h.b.Initialize(ctx, &logical.InitializationRequest{Storage: h.storage}); err != nil {
			t.Fatal(err)
		}
		return h.storedAccount("t").ID
	}
	first := init()
	if len(first) != 36 {
		t.Fatalf("id after start = %q", first)
	}
	if again := init(); again != first {
		t.Errorf("a second start changed the id: %s, was %s", again, first)
	}
	if h.storedAccount("t").PrivateKey != a.PrivateKey {
		t.Error("assigning an id changed the account key")
	}
}
