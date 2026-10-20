// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/torstei/bao-acme/internal/acmetest"
	"github.com/torstei/bao-acme/internal/cert"
)

const (
	eabKeyID  = "kid-1"
	eabHMAC   = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
	testEmail = "ops@example.com"
)

func newAccount(t *testing.T, p *acmetest.Pebble) *Account {
	t.Helper()
	key, err := cert.GenerateKey("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	return &Account{
		DirectoryURL: p.DirectoryURL,
		Email:        testEmail,
		Key:          key,
		CABundle:     []*x509.Certificate{p.CA},
	}
}

func TestRegisterAndRefresh(t *testing.T) {
	p := acmetest.Start(t, acmetest.Options{})
	a := newAccount(t, p)
	ctx := context.Background()

	if _, _, err := Register(ctx, a, false); !errors.Is(err, ErrTermsNotAgreed) {
		t.Fatalf("register without terms: %v", err)
	}

	reg, dir, err := Register(ctx, a, true)
	if err != nil {
		t.Fatal(err)
	}
	if reg.AccountURL == "" || reg.Status != "valid" || dir.TermsOfService == "" {
		t.Fatalf("registration = %+v, directory = %+v", reg, dir)
	}
	if len(reg.Contact) != 1 || reg.Contact[0] != "mailto:"+testEmail {
		t.Errorf("contact = %v", reg.Contact)
	}

	again, _, err := Register(ctx, a, true)
	if err != nil || again.AccountURL != reg.AccountURL {
		t.Errorf("registering the same key again: %+v, %v", again, err)
	}

	a.AccountURL = reg.AccountURL
	a.Email = "new@example.com"
	refreshed, _, err := Refresh(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed.Contact) != 1 || refreshed.Contact[0] != "mailto:new@example.com" {
		t.Errorf("contact after update = %v", refreshed.Contact)
	}
}

func TestExternalAccountBinding(t *testing.T) {
	p := acmetest.Start(t, acmetest.Options{RequireEAB: true, EABKeys: map[string]string{eabKeyID: eabHMAC}})
	ctx := context.Background()

	a := newAccount(t, p)
	if _, _, err := Register(ctx, a, true); !errors.Is(err, ErrEABRequired) {
		t.Fatalf("register without EAB: %v", err)
	}

	a.EABKeyID, a.EABHMACKey = eabKeyID, eabHMAC
	reg, dir, err := Register(ctx, a, true)
	if err != nil {
		t.Fatal(err)
	}
	if !dir.ExternalAccountRequired || reg.Status != "valid" {
		t.Errorf("registration = %+v, directory = %+v", reg, dir)
	}

	wrong := newAccount(t, p)
	wrong.EABKeyID, wrong.EABHMACKey = eabKeyID, "AAAA"+eabHMAC[4:]
	if _, _, err := Register(ctx, wrong, true); err == nil {
		t.Error("registered with a wrong HMAC key")
	}
}

func TestUntrustedServer(t *testing.T) {
	p := acmetest.Start(t, acmetest.Options{})
	a := newAccount(t, p)
	a.CABundle = nil
	if _, _, err := Register(context.Background(), a, true); err == nil {
		t.Error("registered against a server whose certificate is not trusted")
	}
}

func TestResolveDirectoryURL(t *testing.T) {
	cases := map[string]string{
		"letsencrypt-staging":      "https://acme-staging-v02.api.letsencrypt.org/directory",
		"https://acme.example/dir": "https://acme.example/dir",
	}
	for in, want := range cases {
		if got, err := ResolveDirectoryURL(in); err != nil || got != want {
			t.Errorf("ResolveDirectoryURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://acme.example/dir", "nonsense", "https://"} {
		if _, err := ResolveDirectoryURL(bad); err == nil {
			t.Errorf("ResolveDirectoryURL(%q) accepted", bad)
		}
	}
}

func TestContactCurrent(t *testing.T) {
	cases := []struct {
		contact     []string
		email, sent string
		want        bool
	}{
		{nil, "", "", true},
		{[]string{"mailto:a@example.com"}, "a@example.com", "", true},
		{[]string{"mailto:A@example.com"}, "a@example.com", "", true},
		{[]string{"mailto:a@example.com"}, "b@example.com", "a@example.com", false},
		{[]string{"mailto:a@example.com"}, "", "a@example.com", false},
		{nil, "a@example.com", "a@example.com", true},
		{nil, "a@example.com", "", false},
		{nil, "b@example.com", "a@example.com", false},
	}
	for _, c := range cases {
		if got := ContactCurrent(c.contact, c.email, c.sent); got != c.want {
			t.Errorf("ContactCurrent(%v, %q, %q) = %v", c.contact, c.email, c.sent, got)
		}
	}
}

// TestCAKeepingNoContact: Let's Encrypt keeps no contact, so an address the
// CA has been given once is not sent again on every refresh.
func TestCAKeepingNoContact(t *testing.T) {
	p := acmetest.Start(t, acmetest.Options{KeepNoContact: true})
	a := newAccount(t, p)
	ctx := context.Background()

	reg, _, err := Register(ctx, a, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Contact) != 0 || reg.ContactSent != testEmail {
		t.Fatalf("registration = %+v", reg)
	}
	a.AccountURL, a.ContactSent = reg.AccountURL, reg.ContactSent

	for range 2 {
		refreshed, _, err := Refresh(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		a.ContactSent = refreshed.ContactSent
	}
	if n := p.ContactUpdates(); n != 0 {
		t.Errorf("sent the unchanged address %d times", n)
	}

	a.Email = "new@example.com"
	for range 2 {
		refreshed, _, err := Refresh(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		a.ContactSent = refreshed.ContactSent
	}
	if n := p.ContactUpdates(); n != 1 || a.ContactSent != "new@example.com" {
		t.Errorf("a changed address: %d updates, sent %q", n, a.ContactSent)
	}
}
