// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
)

// checkCAA parses each record as a zone file line and checks that it pins
// issuance to accountURL and DNS-01.
func checkCAA(t *testing.T, records []string, accountURL string) {
	t.Helper()
	if len(records) != 2 {
		t.Fatalf("records = %v, want one issue and one issuewild", records)
	}
	tags := map[string]bool{}
	for _, rec := range records {
		rr, err := dns.NewRR("example.test. 3600 IN CAA " + rec)
		if err != nil {
			t.Fatalf("%q is not a valid CAA record: %v", rec, err)
		}
		caa := rr.(*dns.CAA)
		tags[caa.Tag] = true
		parts := strings.Split(caa.Value, ";")
		if strings.TrimSpace(parts[0]) != "pebble.letsencrypt.org" {
			t.Errorf("%q: issuer %q", rec, parts[0])
		}
		params := map[string]string{}
		for _, p := range parts[1:] {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			params[k] = v
		}
		if params["accounturi"] != accountURL || params["validationmethods"] != "dns-01" {
			t.Errorf("%q: parameters %v", rec, params)
		}
	}
	if !tags["issue"] || !tags["issuewild"] {
		t.Errorf("tags = %v", tags)
	}
}

func TestAccountShowsCAARecords(t *testing.T) {
	h := newHarness(t)
	p := acmetest.Start(t, acmetest.Options{})
	created := h.ok(logical.CreateOperation, "config/accounts/a", map[string]any{
		"directory_url":           p.DirectoryURL,
		"ca_bundle":               p.CAPEM,
		"terms_of_service_agreed": true,
	})
	if _, ok := created.Data["caa_records"]; ok {
		t.Error("CAA records shown before the account has a URL")
	}

	reg := h.ok(logical.UpdateOperation, "config/accounts/a/register", nil)
	checkCAA(t, reg.Data["caa_records"].([]string), reg.Data["account_url"].(string))
	if note, _ := reg.Data["caa_note"].(string); !strings.Contains(note, "certbot") {
		t.Errorf("caa_note = %q", note)
	}
	read := h.ok(logical.ReadOperation, "config/accounts/a", nil)
	checkCAA(t, read.Data["caa_records"].([]string), read.Data["account_url"].(string))
}

func TestFirstUseRegistrationKeepsCAAIdentities(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	acct := e.ok(logical.ReadOperation, "config/accounts/le", nil)
	checkCAA(t, acct.Data["caa_records"].([]string), acct.Data["account_url"].(string))
}
