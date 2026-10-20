// SPDX-License-Identifier: MPL-2.0

// Package acmeclient talks to ACME servers through lego, with every input
// passed explicitly: no environment variables, no files.
package acmeclient

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

const mailto = "mailto:"

// Account is what the engine knows about an ACME account.
type Account struct {
	DirectoryURL string
	Email        string
	Key          crypto.Signer
	// CABundle, when set, is trusted for the ACME server's TLS certificate
	// in addition to the system roots.
	CABundle []*x509.Certificate
	// AccountURL is empty until the account is registered.
	AccountURL string
	// ContactSent is the address last given to the CA.
	ContactSent string
	EABKeyID    string
	EABHMACKey  string
	// Network is how to reach the CA; nil means directly.
	Network *Network
}

// Registration is the CA's view of an account.
type Registration struct {
	AccountURL string
	Status     string
	Contact    []string
	// ContactSent is the address last given to the CA.
	ContactSent    string
	TermsOfService string
	// CAAIdentities are the issuer domain names the CA recognises in CAA
	// records, such as "letsencrypt.org".
	CAAIdentities []string
}

// Directory is what the CA's directory says about itself.
type Directory struct {
	TermsOfService          string
	ExternalAccountRequired bool
	CAAIdentities           []string
}

// ErrTermsNotAgreed is returned by Register when the terms of service have
// not been agreed to; the Directory says where to read them.
var ErrTermsNotAgreed = errors.New("the terms of service have not been agreed to")

// ErrEABRequired is returned by Register when the CA requires external
// account binding and the account has none.
var ErrEABRequired = errors.New("the CA requires external account binding (eab_kid and eab_hmac_key)")

// ResolveDirectoryURL accepts an https URL or a CA name known to lego, such
// as "letsencrypt" or "letsencrypt-staging".
func ResolveDirectoryURL(s string) (string, error) {
	if !strings.Contains(s, "://") {
		u, err := lego.GetDirectoryURL(s)
		if err != nil {
			return "", fmt.Errorf("%q is neither a URL nor a known CA name", s)
		}
		return u, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("directory_url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("directory_url must be an https URL")
	}
	return s, nil
}

type user struct {
	a   *Account
	reg *acme.ExtendedAccount
}

func (u *user) GetEmail() string                       { return u.a.Email }
func (u *user) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *user) GetPrivateKey() crypto.Signer           { return u.a.Key }

const userAgent = "bao-acme"

// newClient builds a lego client for a. wrap, when set, wraps the HTTP
// transport, to observe the exchange with the CA.
func newClient(a *Account, wrap ...func(http.RoundTripper) http.RoundTripper) (*lego.Client, *user, error) {
	u := &user{a: a}
	if a.AccountURL != "" {
		u.reg = &acme.ExtendedAccount{Location: a.AccountURL}
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = a.DirectoryURL
	cfg.HTTPClient = a.Network.HTTPClient(a.CABundle)
	for _, w := range wrap {
		cfg.HTTPClient.Transport = w(cfg.HTTPClient.Transport)
	}
	cfg.UserAgent = userAgent
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ACME directory %s: %w", a.DirectoryURL, err)
	}
	return client, u, nil
}

// GetDirectory reads the CA's directory metadata.
func GetDirectory(a *Account) (*Directory, error) {
	client, _, err := newClient(a)
	if err != nil {
		return nil, err
	}
	return directoryOf(client), nil
}

func directoryOf(client *lego.Client) *Directory {
	meta := client.GetServerMetadata()
	return &Directory{
		TermsOfService:          meta.TermsOfService,
		ExternalAccountRequired: meta.ExternalAccountRequired,
		CAAIdentities:           meta.CaaIdentities,
	}
}

// Register creates the account at the CA, or returns it if the CA already
// has an account for this key.
func Register(ctx context.Context, a *Account, termsAgreed bool) (*Registration, *Directory, error) {
	client, _, err := newClient(a)
	if err != nil {
		return nil, nil, err
	}
	dir := directoryOf(client)
	if !termsAgreed && dir.TermsOfService != "" {
		return nil, dir, ErrTermsNotAgreed
	}

	var acct *acme.ExtendedAccount
	switch {
	case a.EABKeyID != "":
		acct, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: termsAgreed,
			Kid:                  a.EABKeyID,
			HmacEncoded:          a.EABHMACKey,
		})
	case dir.ExternalAccountRequired:
		return nil, dir, ErrEABRequired
	default:
		acct, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: termsAgreed})
	}
	if err != nil {
		return nil, dir, fmt.Errorf("registering: %w", err)
	}
	if acct.Location == "" {
		acct, err = client.Registration.ResolveAccountByKey(ctx)
		if err != nil {
			return nil, dir, fmt.Errorf("looking up the existing account: %w", err)
		}
	}
	return registrationOf(acct, dir, a.Email), dir, nil
}

// Refresh reads a registered account from the CA, first updating its
// contact if it differs from a.Email.
func Refresh(ctx context.Context, a *Account) (*Registration, *Directory, error) {
	if a.AccountURL == "" {
		return nil, nil, errors.New("the account is not registered")
	}
	client, _, err := newClient(a)
	if err != nil {
		return nil, nil, err
	}
	dir := directoryOf(client)

	acct, err := client.Registration.QueryRegistration(ctx)
	if err != nil {
		return nil, dir, fmt.Errorf("reading the account: %w", err)
	}
	sent := a.ContactSent
	if !ContactCurrent(acct.Contact, a.Email, sent) {
		acct, err = client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{})
		if err != nil {
			return nil, dir, fmt.Errorf("updating the contact: %w", err)
		}
		sent = a.Email
	}
	return registrationOf(acct, dir, sent), dir, nil
}

// ContactCurrent reports whether the CA has email as the account's contact,
// as far as it keeps one. A CA may keep no contact at all (Let's Encrypt
// forwards the address to a mailing list and returns none), so an empty
// contact counts once email has been sent.
func ContactCurrent(contact []string, email, sent string) bool {
	if email == "" {
		return len(contact) == 0
	}
	if len(contact) == 0 {
		return strings.EqualFold(sent, email)
	}
	return len(contact) == 1 && strings.EqualFold(contact[0], mailto+email)
}

func registrationOf(acct *acme.ExtendedAccount, dir *Directory, sent string) *Registration {
	return &Registration{
		AccountURL:     acct.Location,
		Status:         acct.Status,
		Contact:        acct.Contact,
		ContactSent:    sent,
		TermsOfService: dir.TermsOfService,
		CAAIdentities:  dir.CAAIdentities,
	}
}
