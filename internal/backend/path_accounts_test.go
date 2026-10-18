// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmetest"
)

const (
	testEABKeyID = "kid-1"
	testEABHMAC  = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
)

func (h *harness) storedAccount(name string) *accountEntry {
	h.t.Helper()
	a, err := loadAccount(context.Background(), h.storage, name)
	if err != nil || a == nil {
		h.t.Fatalf("account %s: %v", name, err)
	}
	return a
}

func TestAccountLifecycle(t *testing.T) {
	h := newHarness(t)
	p := acmetest.Start(t, acmetest.Options{})

	created := h.ok(logical.CreateOperation, "config/accounts/test", map[string]any{
		"directory_url": p.DirectoryURL,
		"email":         "ops@example.com",
		"ca_bundle":     p.CAPEM,
	})
	if created.Data["registered"] != false || created.Data["key_type"] != "ecdsa-p256" {
		t.Fatalf("created = %v", created.Data)
	}
	for _, secret := range []string{"private_key", "eab_hmac_key"} {
		if _, ok := created.Data[secret]; ok {
			t.Errorf("response contains %s", secret)
		}
	}
	key := h.storedAccount("test").PrivateKey
	if !strings.Contains(key, "PRIVATE KEY") {
		t.Fatal("no account key generated")
	}

	h.fails(logical.UpdateOperation, "config/accounts/test/register", nil, "terms_of_service_agreed=true")

	h.ok(logical.UpdateOperation, "config/accounts/test", map[string]any{"terms_of_service_agreed": true})
	reg := h.ok(logical.UpdateOperation, "config/accounts/test/register", nil)
	url, _ := reg.Data["account_url"].(string)
	if reg.Data["registered"] != true || reg.Data["status"] != "valid" || url == "" {
		t.Fatalf("registered = %v", reg.Data)
	}
	if got := reg.Data["registered_contact"].([]string); len(got) != 1 || got[0] != "mailto:ops@example.com" {
		t.Errorf("registered_contact = %v", got)
	}

	changed := h.ok(logical.UpdateOperation, "config/accounts/test", map[string]any{"email": "new@example.com"})
	if len(changed.Warnings) != 1 {
		t.Errorf("no warning about the contact differing: %v", changed.Warnings)
	}
	again := h.ok(logical.UpdateOperation, "config/accounts/test/register", nil)
	if again.Data["account_url"] != url {
		t.Errorf("account_url changed: %v", again.Data["account_url"])
	}
	if got := again.Data["registered_contact"].([]string); len(got) != 1 || got[0] != "mailto:new@example.com" {
		t.Errorf("registered_contact after update = %v", got)
	}

	h.fails(logical.UpdateOperation, "config/accounts/test", map[string]any{"directory_url": "letsencrypt-staging"}, "cannot change")
	h.fails(logical.UpdateOperation, "config/accounts/test", map[string]any{"key_type": "rsa-2048"}, "cannot change")
	h.fails(logical.UpdateOperation, "config/accounts/test", map[string]any{"eab_kid": "x", "eab_hmac_key": "eHg"}, "already registered")

	if h.storedAccount("test").PrivateKey != key {
		t.Error("account key changed")
	}

	if keys := h.ok(logical.ListOperation, "config/accounts/", nil).Data["keys"].([]string); strings.Join(keys, ",") != "t,test" {
		t.Errorf("list = %v", keys)
	}
	deleted := h.ok(logical.DeleteOperation, "config/accounts/test", nil)
	if deleted == nil || len(deleted.Warnings) != 1 {
		t.Errorf("deleting a registered account gave no warning: %v", deleted)
	}
	if resp, _ := h.do(logical.ReadOperation, "config/accounts/test", nil); resp != nil {
		t.Error("account still readable after delete")
	}
}

func TestAccountExternalAccountBinding(t *testing.T) {
	h := newHarness(t)
	p := acmetest.Start(t, acmetest.Options{RequireEAB: true, EABKeys: map[string]string{testEABKeyID: testEABHMAC}})

	h.ok(logical.CreateOperation, "config/accounts/eab", map[string]any{
		"directory_url":           p.DirectoryURL,
		"ca_bundle":               p.CAPEM,
		"terms_of_service_agreed": true,
	})
	h.fails(logical.UpdateOperation, "config/accounts/eab/register", nil, "external account binding")

	written := h.ok(logical.UpdateOperation, "config/accounts/eab", map[string]any{
		"eab_kid":      testEABKeyID,
		"eab_hmac_key": testEABHMAC,
	})
	if written.Data["eab_hmac_key_set"] != true || written.Data["eab_kid"] != testEABKeyID {
		t.Errorf("after setting EAB: %v", written.Data)
	}
	if reg := h.ok(logical.UpdateOperation, "config/accounts/eab/register", nil); reg.Data["status"] != "valid" {
		t.Errorf("registered = %v", reg.Data)
	}
}

func TestAccountValidation(t *testing.T) {
	h := newHarness(t)
	const path = "config/accounts/v"

	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "http://acme.example/dir"}, "https")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "nope"}, "known CA name")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt", "key_type": "dsa"}, "unsupported key type")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt", "email": "a@b.c, d@e.f"}, "single address")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt", "eab_kid": "x"}, "set together")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt", "eab_kid": "x", "eab_hmac_key": "not base64!"}, "base64url")
	h.fails(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt", "ca_bundle": "junk"}, "ca_bundle")
	if resp, _ := h.do(logical.ReadOperation, path, nil); resp != nil {
		t.Fatal("a rejected write was stored")
	}

	ok := h.ok(logical.CreateOperation, path, map[string]any{"directory_url": "letsencrypt-staging", "email": "mailto:ops@example.com", "key_type": "rsa-2048"})
	if ok.Data["directory_url"] != "https://acme-staging-v02.api.letsencrypt.org/directory" || ok.Data["email"] != "ops@example.com" {
		t.Errorf("created = %v", ok.Data)
	}
	h.fails(logical.UpdateOperation, "config/accounts/missing/register", nil, "no account")

	h.ok(logical.CreateOperation, "config/accounts/imports-only", map[string]any{"email": "ops@example.com"})
	h.fails(logical.UpdateOperation, "config/accounts/imports-only/register", nil, "no directory_url")
}
